"""扫描器识别模型 v3 - 基于新华人寿WAF日志分析实战提炼

决策树+评分混合模型，4个行为维度6条决策规则。
确定性逻辑，不依赖LLM。
"""

import pandas as pd
import re
from collections import Counter
from dataclasses import dataclass, field

SCANNER_UA_KEYWORDS = [
    "nmap", "nikto", "sqlmap", "dirbuster", "gobuster", "wfuzz",
    "burp", "masscan", "zgrab", "nuclei", "httpx", "feroxbuster",
    "w3af", "acunetix", "nessus", "openvas", "qualys", "rapid7",
    "scanner", "bot", "crawler", "spider", "curl/", "wget/",
    "python-requests", "go-http-client", "java/", "apache-httpclient",
]

SCANNER_SCORE_THRESHOLD = 60


@dataclass
class ScannerScore:
    ip: str
    score: float = 0
    is_scanner: bool = False
    ua_count: int = 0
    ua_list: list = field(default_factory=list)
    scanner_ua_ratio: float = 0.0
    url_diversity: float = 0.0
    request_count: int = 0
    target_host_count: int = 0
    has_200: bool = False
    scanner_tag_ratio: float = 0.0
    fixed_payload: bool = False
    rules_triggered: list = field(default_factory=list)
    attack_types: dict = field(default_factory=dict)


def _extract_ua(req_header: str) -> str:
    if not isinstance(req_header, str):
        return ""
    match = re.search(r'User-Agent:\s*(.+)', req_header)
    return match.group(1).strip()[:200] if match else ""


def _is_scanner_ua(ua: str) -> bool:
    ua_lower = ua.lower()
    return any(kw in ua_lower for kw in SCANNER_UA_KEYWORDS)


def compute_url_diversity(urls: pd.Series) -> float:
    if len(urls) == 0:
        return 0.0
    unique = urls.nunique()
    return unique / len(urls) if len(urls) > 0 else 0.0


def identify_scanners(
    df: pd.DataFrame,
    score_threshold: float = SCANNER_SCORE_THRESHOLD,
    min_requests: int = 5,
) -> list[ScannerScore]:
    """对DataFrame中的源IP进行扫描器识别。

    Args:
        df: WAF日志DataFrame，必须包含src_ip, url_path, attack_type列
            以及req_header列(用于提取UA)
        score_threshold: 扫描器判定分数阈值
        min_requests: 最小请求数，低于此数不进行评分

    Returns:
        所有IP的扫描器评分列表
    """
    results = []

    for ip, group in df.groupby("src_ip"):
        s = ScannerScore(ip=ip, request_count=len(group))

        if len(group) < min_requests:
            results.append(s)
            continue

        # 提取UA
        if "req_header" in df.columns:
            uas = group["req_header"].apply(_extract_ua)
            ua_series = uas[uas != ""]
            s.ua_list = ua_series.unique().tolist()[:50]
            s.ua_count = len(s.ua_list)

            if s.ua_count > 0:
                scanner_ua_count = sum(1 for u in s.ua_list if _is_scanner_ua(u))
                s.scanner_ua_ratio = scanner_ua_count / s.ua_count

        # URL多样性
        s.url_diversity = compute_url_diversity(group["url_path"])

        # 目标Host数
        if "host" in df.columns:
            s.target_host_count = group["host"].nunique()

        # 是否有200响应
        if "status_code" in df.columns:
            s.has_200 = (group["status_code"] == 200).any()

        # WAF扫描器标签比例
        if "attack_type" in df.columns:
            scanner_count = (group["attack_type"] == "扫描器").sum()
            s.scanner_tag_ratio = scanner_count / len(group)
            s.attack_types = group["attack_type"].value_counts().head(10).to_dict()

        # 固定payload检测
        if "url_path" in df.columns:
            url_counts = group["url_path"].value_counts()
            if len(url_counts) > 0:
                top_url_ratio = url_counts.iloc[0] / len(group)
                s.fixed_payload = top_url_ratio > 0.8

        # === 6条决策规则 ===

        # 规则1: UA轮换数量 >= 10 → 扫描器(score=80)
        if s.ua_count >= 10:
            s.score = max(s.score, 80)
            s.rules_triggered.append("UA轮换>=10")

        # 规则2: 扫描器关键词占比 >= 50% → 扫描器(score=85)
        if s.scanner_ua_ratio >= 0.5:
            s.score = max(s.score, 85)
            s.rules_triggered.append("扫描器UA占比>=50%")

        # 规则3: 请求模式(高URL多样性+高频+无200) → 扫描器(score=70)
        freq_per_hour = len(group) / max(1, 36)  # 假设36小时数据
        if s.url_diversity >= 0.85 and freq_per_hour >= 20 and not s.has_200:
            s.score = max(s.score, 70)
            s.rules_triggered.append("高频高多样性无200")

        # 规则4: WAF扫描器标签>=80% + 多UA/固定payload → 扫描器(score=75)
        if s.scanner_tag_ratio >= 0.8 and (s.ua_count >= 3 or s.fixed_payload):
            s.score = max(s.score, 75)
            s.rules_triggered.append("WAF标记+自动化行为")

        # 规则5: 固定payload+多UA+请求数>=30 → 扫描器(score=65)
        if s.fixed_payload and s.ua_count >= 5 and len(group) >= 30:
            s.score = max(s.score, 65)
            s.rules_triggered.append("固定payload+多UA")

        # 规则6: 多站点+高404 → 扫描器(score=65)
        if "status_code" in df.columns:
            not_found_ratio = (group["status_code"] == 404).sum() / len(group)
            if s.target_host_count >= 5 and not_found_ratio >= 0.6 and len(group) >= 50:
                s.score = max(s.score, 65)
                s.rules_triggered.append("多站点+高404")

        # 特殊规则: 纯扫描器类型告警 + 高请求量 → 提高分数
        if s.scanner_tag_ratio >= 0.95 and len(group) >= 100:
            s.score = max(s.score, 90)
            if "纯扫描器高请求量" not in s.rules_triggered:
                s.rules_triggered.append("纯扫描器高请求量")

        s.is_scanner = s.score >= score_threshold
        results.append(s)

    results.sort(key=lambda x: x.score, reverse=True)
    return results
