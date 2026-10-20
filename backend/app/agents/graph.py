"""WAF日志分析引擎 - LangGraph工作流

工作流: ingest → identify → analyze → generate → [HITL] → deploy → report
确定性逻辑直接执行，推理逻辑调用LLM，人工干预门使用interrupt。
"""

import pandas as pd
import json
import logging
from typing import TypedDict, Optional, Annotated
from langgraph.graph import StateGraph, END

from app.analyzers.scanner_detector import identify_scanners, ScannerScore
from app.analyzers.ip_profiler import profile_ips, IPProfile
from app.analyzers.subnet_grouper import aggregate_subnets, SubnetInfo
from app.analyzers.pattern_extractor import recommend_rule_strategy, PatternRecommendation
from app.analyzers.coverage_calculator import calculate_coverage

logger = logging.getLogger(__name__)

# DataFrame缓存，避免序列化问题（LangGraph不支持DataFrame在state中传递）
_df_cache: dict[str, pd.DataFrame] = {}


class AnalysisState(TypedDict, total=False):
    # 输入
    project_id: str
    raw_log_path: str

    # 数据摄入阶段
    total_logs: int
    df_cache_key: str
    attack_type_distribution: dict
    time_range_start: str
    time_range_end: str
    all_internal: bool

    # 扫描器识别阶段
    scanner_scores: list[dict]
    scanner_ip_count: int
    scanner_log_count: int
    non_scanner_log_count: int

    # IP画像和子网聚合
    ip_profiles: dict
    subnet_infos: list[dict]

    # 根因分析阶段
    root_causes: list[dict]
    coverage_before: float

    # 规则生成阶段
    proposed_rules: list[dict]
    coverage_after: float
    coverage_improvement: float

    # 人工确认阶段
    approved_rule_indices: list[int]
    rejected_rule_indices: list[int]

    # 部署阶段
    deployment_results: list[dict]

    # 报告阶段
    report_markdown: str
    report_path: str

    # 元数据
    current_step: str
    error: Optional[str]


def _read_json_log(log_path: str, max_rows: int = 100000) -> pd.DataFrame:
    """读取JSON日志文件，支持大文件。
    逐行解析，读到max_rows停止，分批构建DataFrame控制内存。
    自动裁剪超大字段（payload等）避免内存爆炸。"""
    # 分析不需要的大字段，读取时直接丢弃
    DROP_FIELDS = {"payload", "req_body", "resp_body", "stack_trace"}
    # 超长字段截断
    MAX_FIELD_LEN = 500
    chunk_size = 5000
    chunks = []
    records = []

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        first_char = f.read(1).strip()
        f.seek(0)

        if first_char == "[":
            for line in f:
                line = line.strip()
                if line in ("[", "]", ""):
                    continue
                if line.endswith(","):
                    line = line[:-1]
                try:
                    rec = json.loads(line)
                    for k in DROP_FIELDS:
                        rec.pop(k, None)
                    for k, v in rec.items():
                        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
                            rec[k] = v[:MAX_FIELD_LEN]
                    records.append(rec)
                except json.JSONDecodeError:
                    continue
                if len(records) >= chunk_size:
                    chunks.append(pd.DataFrame(records))
                    records = []
                    if sum(len(c) for c in chunks) >= max_rows:
                        break
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    for k in DROP_FIELDS:
                        rec.pop(k, None)
                    for k, v in rec.items():
                        if isinstance(v, str) and len(v) > MAX_FIELD_LEN:
                            rec[k] = v[:MAX_FIELD_LEN]
                    records.append(rec)
                except json.JSONDecodeError:
                    continue
                if len(records) >= chunk_size:
                    chunks.append(pd.DataFrame(records))
                    records = []
                    if sum(len(c) for c in chunks) >= max_rows:
                        break

    if records:
        chunks.append(pd.DataFrame(records))

    if not chunks:
        return pd.DataFrame()
    return pd.concat(chunks, ignore_index=True)


def ingest_node(state: AnalysisState) -> dict:
    """数据摄入：解析WAF日志文件，支持大文件流式读取"""
    log_path = state.get("raw_log_path", "")
    if not log_path:
        return {"error": "未提供日志文件路径", "current_step": "ingest_failed"}

    # 读取日志
    if log_path.endswith(".pkl"):
        df = pd.read_pickle(log_path)
    elif log_path.endswith(".json"):
        df = _read_json_log(log_path)
    elif log_path.endswith(".csv"):
        df = pd.read_csv(log_path)
    else:
        return {"error": f"不支持的日志格式: {log_path}", "current_step": "ingest_failed"}

    if df is None or len(df) == 0:
        return {"error": "日志文件为空或解析失败", "current_step": "ingest_failed"}

    total = len(df)

    # 攻击类型分布
    if "attack_type" in df.columns:
        dist = df["attack_type"].value_counts().to_dict()
    else:
        dist = {}

    # 是否全部内网IP
    all_internal = True
    if "src_ip" in df.columns:
        all_internal = df["src_ip"].apply(
            lambda x: str(x).startswith(("10.", "172.", "192.168."))
        ).all()

    # 时间范围
    time_start = ""
    time_end = ""
    if "human_req_start_time" in df.columns:
        times = df["human_req_start_time"].dropna()
        if len(times) > 0:
            time_start = str(times.min())
            time_end = str(times.max())

    # DataFrame存入缓存，state中只存key
    cache_key = f"{state.get('project_id', 'unknown')}_{id(df)}"
    _df_cache[cache_key] = df

    return {
        "total_logs": total,
        "df_cache_key": cache_key,
        "attack_type_distribution": dist,
        "all_internal": all_internal,
        "time_range_start": time_start,
        "time_range_end": time_end,
        "current_step": "ingest_done",
    }


def identify_node(state: AnalysisState) -> dict:
    """扫描器识别：使用决策树+评分模型"""
    df = _df_cache.get(state.get("df_cache_key", ""))
    if df is None or len(df) == 0:
        return {"error": "无日志数据", "current_step": "identify_failed"}

    scores = identify_scanners(df)

    scanner_ips = [s for s in scores if s.is_scanner]
    scanner_log_count = sum(s.request_count for s in scanner_ips)

    # 序列化评分结果
    scores_data = []
    for s in scores:
        scores_data.append({
            "ip": s.ip,
            "score": s.score,
            "is_scanner": s.is_scanner,
            "ua_count": s.ua_count,
            "scanner_ua_ratio": s.scanner_ua_ratio,
            "url_diversity": s.url_diversity,
            "request_count": s.request_count,
            "rules_triggered": s.rules_triggered,
            "attack_types": s.attack_types,
        })

    return {
        "scanner_scores": scores_data,
        "scanner_ip_count": len(scanner_ips),
        "scanner_log_count": scanner_log_count,
        "non_scanner_log_count": state["total_logs"] - scanner_log_count,
        "current_step": "identify_done",
    }


async def analyze_node(state: AnalysisState) -> dict:
    """根因分析：IP画像+子网聚合+业务归类+LLM增强推理"""
    df = _df_cache.get(state.get("df_cache_key", ""))
    if df is None:
        return {"error": "无日志数据", "current_step": "analyze_failed"}

    # IP画像
    profiles = profile_ips(df)

    # 序列化IP画像
    profiles_data = {}
    for ip, p in profiles.items():
        profiles_data[ip] = {
            "ip": p.ip,
            "request_count": p.request_count,
            "ua_list": p.ua_list,
            "target_hosts": p.target_hosts,
            "attack_types": p.attack_types,
            "url_diversity": p.url_diversity,
            "subnet_24": p.subnet_24,
            "is_internal": p.is_internal,
        }

    # 子网聚合
    subnets = aggregate_subnets(df)

    # 序列化子网信息
    subnets_data = []
    for s in subnets:
        subnets_data.append({
            "cidr": s.cidr,
            "log_count": s.log_count,
            "ip_count": s.ip_count,
            "ip_list": s.ip_list,
            "attack_types": s.attack_types,
            "target_hosts": s.target_hosts,
            "top_urls": s.top_urls,
            "rule_strategy": s.rule_strategy,
        })

    # 确定性根因分类
    deterministic_causes = _classify_root_causes(state, profiles, subnets)

    # LLM增强根因分析
    llm_causes = await _llm_root_cause_analysis(state, profiles, subnets, df)

    # 合并：LLM结果补充确定性结果中缺失的洞察
    root_causes = _merge_root_causes(deterministic_causes, llm_causes)

    return {
        "ip_profiles": profiles_data,
        "subnet_infos": subnets_data,
        "root_causes": root_causes,
        "coverage_before": 0.0,
        "current_step": "analyze_done",
    }


def _classify_root_causes(
    state: AnalysisState,
    profiles: dict,
    subnets: list,
) -> list[dict]:
    """基于分析结果进行根因分类。"""
    causes = []
    df = _df_cache.get(state.get("df_cache_key", ""))
    if df is None:
        return causes

    # 按攻击类型分组统计
    if "attack_type" not in df.columns:
        return causes

    # 扫描器误判
    scanner_count = state.get("scanner_log_count", 0)
    if scanner_count > 0:
        causes.append({
            "category": "扫描器误判",
            "log_count": scanner_count,
            "percentage": scanner_count / len(df) * 100,
            "description": "业务正常流量触发扫描器检测规则",
        })

    # SQL注入误报
    sql_count = (df["attack_type"] == "SQL 注入").sum()
    if sql_count > 0:
        causes.append({
            "category": "SQL注入误报",
            "log_count": int(sql_count),
            "percentage": sql_count / len(df) * 100,
            "description": "业务组件直接传递SQL查询语句",
        })

    # 目录穿越误报
    dt_count = (df["attack_type"] == "目录穿越").sum()
    if dt_count > 0:
        causes.append({
            "category": "目录穿越误报",
            "log_count": int(dt_count),
            "percentage": dt_count / len(df) * 100,
            "description": "业务组件路径参数触发目录穿越检测",
        })

    # 其他类型
    for at in ["信息泄露", "XSS", "命令注入", "文件包含", "SSRF", "LDAP 注入"]:
        count = (df["attack_type"] == at).sum()
        if count > 0:
            causes.append({
                "category": f"{at}误报",
                "log_count": int(count),
                "percentage": count / len(df) * 100,
                "description": f"业务系统请求模式触发{at}检测规则",
            })

    return causes


async def generate_node(state: AnalysisState) -> dict:
    """规则生成：基于分析结果自动生成检测模块控制规则，LLM优化命名"""
    df = _df_cache.get(state.get("df_cache_key", ""))
    if df is None:
        return {"error": "无日志数据", "current_step": "generate_failed"}

    proposed_rules = []

    # 按攻击类型+URL模式分组，生成规则
    if "attack_type" in df.columns and "url_path" in df.columns:
        non_scanner = df[df["attack_type"] != "扫描器"]

        # 对非扫描器告警按URL模式分组
        for attack_type, group in non_scanner.groupby("attack_type"):
            if len(group) < 5:
                continue

            # 提取URL模式
            url_patterns = group["url_path"].value_counts().head(10)
            for url_pattern, count in url_patterns.items():
                if count < 5:
                    continue
                if not isinstance(url_pattern, str) or not url_pattern.startswith("/"):
                    continue

                # 获取该URL的Host分布
                url_group = group[group["url_path"] == url_pattern]
                if "host" in url_group.columns:
                    hosts = url_group["host"].value_counts().head(3).to_dict()
                else:
                    hosts = {}

                # 推荐规则策略
                rec = recommend_rule_strategy(url_group)

                # 确定关闭的检测模块
                disabled_modules = _get_disabled_modules(attack_type)

                # 确定性生成规则名
                rule_name = _generate_rule_name(url_pattern, attack_type)
                rule_comment = f"{rule_name}触发{attack_type}检测误报消除"

                # 生成规则
                rule = {
                    "name": rule_name,
                    "comment": rule_comment,
                    "action": "modify_module",
                    "pattern_type": rec.strategy.replace("_rule", ""),
                    "pattern": _build_pattern(rec, url_pattern, hosts),
                    "disabled_modules": disabled_modules,
                    "is_enabled": False,
                    "coverage_count": count,
                    "attack_type": attack_type,
                    "strategy": rec.strategy,
                    "confidence": rec.confidence,
                    "url_pattern": url_pattern,
                    "hosts": list(hosts.keys()),
                    "ip_count": url_group["src_ip"].nunique() if "src_ip" in url_group.columns else 0,
                }
                proposed_rules.append(rule)

    # 对扫描器告警生成CIDR/Host规则
    scanner_df = df[df["attack_type"] == "扫描器"]
    if len(scanner_df) > 0:
        subnets = aggregate_subnets(scanner_df, min_count=50)
        for subnet in subnets[:10]:
            rule = {
                "name": f"扫描器误判_{subnet.cidr}",
                "comment": f"{subnet.cidr}网段触发扫描器检测误报消除",
                "action": "modify_module",
                "pattern_type": "cidr",
                "pattern": {
                    "cidr_list": [subnet.cidr],
                },
                "disabled_modules": ["机器人检测"],
                "is_enabled": False,
                "coverage_count": subnet.log_count,
                "attack_type": "扫描器",
                "strategy": "cidr_rule",
                "confidence": 0.7,
            }
            proposed_rules.append(rule)

    # 按覆盖数降序
    proposed_rules.sort(key=lambda x: x["coverage_count"], reverse=True)

    # LLM增强：批量优化规则命名
    await _llm_enhance_rule_names(proposed_rules)

    return {
        "proposed_rules": proposed_rules,
        "current_step": "generate_done",
    }


def _get_disabled_modules(attack_type: str) -> list[str]:
    """根据攻击类型确定需要关闭的检测模块。"""
    mapping = {
        "SQL 注入": ["SQL注入检测"],
        "目录穿越": ["情报模块"],
        "信息泄露": ["情报模块"],
        "超时": ["情报模块", "服务器响应检测"],
        "XSS": ["XSS检测"],
        "命令注入": ["命令注入检测"],
        "文件包含": ["文件包含检测"],
        "SSRF": ["SSRF检测"],
        "LDAP 注入": ["LDAP注入检测"],
        "扫描器": ["机器人检测"],
        "代码执行": ["代码执行检测"],
        "代码注入": ["代码注入检测"],
        "文件上传": ["文件上传检测"],
        "XXE": ["XXE检测"],
        "反序列化": ["反序列化检测"],
    }
    return mapping.get(attack_type, [])


def _generate_rule_name(url: str, attack_type: str) -> str:
    """根据URL和攻击类型生成规则名称。"""
    # 提取URL中的关键词
    parts = url.strip("/").split("/")
    # 取第一个有意义的路径段
    for part in parts:
        if part and not part.startswith("?") and len(part) > 2:
            # 清理文件扩展名
            name = part.split(".")[0].split("?")[0]
            if name and len(name) > 2:
                return name
    return f"业务系统{attack_type}"


def _build_pattern(rec: PatternRecommendation, url: str, hosts: dict) -> dict:
    """构建SafeLine Pattern DSL。"""
    pattern = {}

    if rec.strategy == "url_rule" and rec.url_pattern:
        conditions = [{"infix": {"urlpath": rec.url_pattern}, "decode_methods": []}]
        if len(hosts) > 0 and rec.host_pattern:
            conditions.append({"infix": {"host": rec.host_pattern}, "decode_methods": []})
        if len(conditions) > 1:
            pattern = {"$AND": conditions}
        else:
            pattern = conditions[0]
    elif rec.strategy == "cidr_rule" and rec.cidr_list:
        cidr_conditions = [{"cidr": {"remote_addr": c}, "decode_methods": []} for c in rec.cidr_list]
        if len(cidr_conditions) > 1:
            pattern = {"$OR": cidr_conditions}
        else:
            pattern = cidr_conditions[0]
    elif rec.strategy == "single_ip_rule" and rec.single_ips:
        ip_conditions = [{"str": {"remote_addr": ip}, "decode_methods": []} for ip in rec.single_ips]
        if len(ip_conditions) > 1:
            pattern = {"$OR": ip_conditions}
        else:
            pattern = ip_conditions[0]
    else:
        pattern = {"infix": {"urlpath": url.split("?")[0][:50]}, "decode_methods": []}

    return pattern


async def _llm_root_cause_analysis(
    state: AnalysisState,
    profiles: dict,
    subnets: list,
    df: pd.DataFrame,
) -> list[dict]:
    """LLM增强根因分析。失败时静默返回空列表，不影响确定性分析。"""
    try:
        from app.llm.factory import get_llm
        from app.llm.prompts import ROOT_CAUSE_SYSTEM, ROOT_CAUSE_USER

        llm = get_llm("smart")

        # 构建IP画像摘要
        top_profiles = sorted(profiles.values(), key=lambda p: p.request_count, reverse=True)[:10]
        ip_summary_lines = []
        for p in top_profiles:
            ip_summary_lines.append(
                f"  IP {p.ip}: {p.request_count}次请求, UA数={len(p.ua_list)}, "
                f"URL多样性={p.url_diversity:.2f}, 攻击类型={p.attack_types}"
            )
        ip_summary = "\n".join(ip_summary_lines)

        # 构建子网摘要
        subnet_summary_lines = []
        for s in subnets[:5]:
            subnet_summary_lines.append(
                f"  {s.cidr}: {s.log_count}条告警, {s.ip_count}个IP, "
                f"攻击类型={s.attack_types}, 目标={s.target_hosts}"
            )
        subnet_summary = "\n".join(subnet_summary_lines)

        # 构建URL分布
        url_dist = {}
        if "url_path" in df.columns and "attack_type" in df.columns:
            non_scanner = df[df["attack_type"] != "扫描器"]
            url_dist = non_scanner["url_path"].value_counts().head(10).to_dict()
        url_dist_str = "\n".join(f"  {u}: {c}" for u, c in url_dist.items())

        total = state.get("total_logs", len(df))
        scanner_count = state.get("scanner_log_count", 0)
        scanner_pct = f"{scanner_count / total * 100:.1f}" if total > 0 else "0"

        user_prompt = ROOT_CAUSE_USER.format(
            total_logs=total,
            attack_type_distribution=state.get("attack_type_distribution", {}),
            scanner_log_count=scanner_count,
            scanner_pct=scanner_pct,
            ip_summary=ip_summary,
            subnet_summary=subnet_summary,
            url_distribution=url_dist_str,
        )

        response = await llm.generate(
            system_prompt=ROOT_CAUSE_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.2,
        )

        # 解析JSON
        content = response.content
        json_start = content.find("[")
        json_end = content.rfind("]") + 1
        if json_start >= 0 and json_end > json_start:
            causes = json.loads(content[json_start:json_end])
            return causes

        return []

    except Exception as e:
        logger.warning(f"LLM根因分析失败，使用确定性结果: {e}")
        return []


def _merge_root_causes(deterministic: list[dict], llm: list[dict]) -> list[dict]:
    """合并确定性根因和LLM根因。LLM结果补充描述，确定性结果提供基础数据。"""
    if not llm:
        return deterministic

    # 用LLM结果中的描述增强确定性结果
    category_map = {c["category"]: c for c in deterministic}

    for llm_cause in llm:
        category = llm_cause.get("category", "")
        # 如果LLM发现了确定性分析未覆盖的根因，直接加入
        if category not in category_map:
            deterministic.append(llm_cause)
        else:
            # 用LLM的描述和建议操作增强
            existing = category_map[category]
            if llm_cause.get("description") and len(llm_cause["description"]) > len(existing.get("description", "")):
                existing["description"] = llm_cause["description"]
            if llm_cause.get("suggested_action"):
                existing["suggested_action"] = llm_cause["suggested_action"]

    return deterministic


async def _llm_enhance_rule_names(rules: list[dict]) -> None:
    """LLM增强规则命名。失败时保持原始命名不变。"""
    if not rules:
        return

    try:
        from app.llm.factory import get_llm
        from app.llm.prompts import RULE_NAMING_SYSTEM, RULE_NAMING_USER

        llm = get_llm("fast")

        # 只对非扫描器规则做LLM命名（扫描器规则名称已足够清晰）
        for rule in rules:
            if rule.get("attack_type") == "扫描器":
                continue
            if "url_pattern" not in rule:
                continue

            try:
                user_prompt = RULE_NAMING_USER.format(
                    url_pattern=rule.get("url_pattern", ""),
                    attack_type=rule.get("attack_type", ""),
                    coverage_count=rule.get("coverage_count", 0),
                    disabled_modules=", ".join(rule.get("disabled_modules", [])),
                    hosts=", ".join(rule.get("hosts", [])),
                    ip_count=rule.get("ip_count", 0),
                )

                response = await llm.generate(
                    system_prompt=RULE_NAMING_SYSTEM,
                    user_prompt=user_prompt,
                    temperature=0.2,
                    max_tokens=256,
                )

                content = response.content
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    naming = json.loads(content[json_start:json_end])
                    if naming.get("name"):
                        rule["name"] = naming["name"]
                    if naming.get("comment"):
                        rule["comment"] = naming["comment"]

            except Exception as e:
                logger.warning(f"规则命名LLM调用失败，保持原始名称: {e}")
                continue

    except Exception as e:
        logger.warning(f"LLM规则命名初始化失败: {e}")


def build_analysis_graph():
    """构建分析工作流图。"""
    graph = StateGraph(AnalysisState)

    graph.add_node("ingest", ingest_node)
    graph.add_node("identify", identify_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("generate", generate_node)

    graph.add_edge("ingest", "identify")
    graph.add_edge("identify", "analyze")
    graph.add_edge("analyze", "generate")
    graph.add_edge("generate", END)

    graph.set_entry_point("ingest")

    return graph.compile()
