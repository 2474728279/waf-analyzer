"""URL/Host模式提取模块 - 从IP组中提取公共URL模式，推荐规则策略"""

import pandas as pd
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PatternRecommendation:
    strategy: str  # "url_rule" | "cidr_rule" | "single_ip_rule"
    confidence: float  # 0-1
    url_pattern: Optional[str] = None
    url_match_type: str = "infix"  # "infix" | "str" | "re"
    host_pattern: Optional[str] = None
    host_match_type: str = "infix"  # "infix" | "str"
    cidr_list: list[str] = field(default_factory=list)
    single_ips: list[str] = field(default_factory=list)
    reason: str = ""


def extract_url_patterns(urls: pd.Series) -> list[dict]:
    """从URL列表中提取公共模式。

    Returns:
        [{"pattern": "/api/xxx", "match_type": "infix", "count": 100}, ...]
    """
    if len(urls) == 0:
        return []

    patterns = []

    # 提取URL路径前缀（前3级路径）
    prefix_counts = {}
    for url in urls:
        if not isinstance(url, str) or not url.startswith("/"):
            continue
        parts = url.split("?")[0].split("/")
        # 取前3级
        prefix = "/".join(parts[:4])
        if len(prefix) > 3:
            prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1

    for prefix, count in sorted(prefix_counts.items(), key=lambda x: -x[1]):
        if count >= 5:
            patterns.append({
                "pattern": prefix,
                "match_type": "infix",
                "count": count,
            })

    return patterns[:10]


def recommend_rule_strategy(
    ip_group_df: pd.DataFrame,
    min_url_coverage: float = 0.7,
) -> PatternRecommendation:
    """为一批同组IP推荐规则策略。

    Args:
        ip_group_df: 同一组IP的日志DataFrame
        min_url_coverage: URL模式需覆盖的最小比例

    Returns:
        规则策略推荐
    """
    rec = PatternRecommendation(strategy="cidr_rule", confidence=0.5)

    url_patterns = extract_url_patterns(ip_group_df["url_path"])

    if url_patterns:
        top_pattern = url_patterns[0]
        coverage = top_pattern["count"] / len(ip_group_df)

        if coverage >= min_url_coverage:
            # URL模式覆盖率高 → URL规则
            rec.strategy = "url_rule"
            rec.confidence = min(1.0, coverage + 0.1)
            rec.url_pattern = top_pattern["pattern"]
            rec.url_match_type = top_pattern["match_type"]
            rec.reason = (
                f"URL模式'{top_pattern['pattern']}'覆盖{coverage:.0%}的请求，"
                f"建议使用URL规则精确匹配"
            )
            return rec

    # 检查是否单IP
    ip_count = ip_group_df["src_ip"].nunique()
    if ip_count == 1:
        rec.strategy = "single_ip_rule"
        rec.confidence = 0.8
        rec.single_ips = ip_group_df["src_ip"].unique().tolist()
        rec.reason = "仅1个源IP，建议使用单IP规则"
        return rec

    # 检查Host是否集中
    if "host" in ip_group_df.columns:
        host_counts = ip_group_df["host"].value_counts()
        if len(host_counts) == 1:
            rec.host_pattern = host_counts.index[0]
            rec.host_match_type = "str"
            rec.confidence = 0.7
            rec.reason = f"目标Host唯一({rec.host_pattern})，CIDR规则加Host限定"

    # CIDR规则
    subnets = ip_group_df["src_ip"].apply(
        lambda x: ".".join(str(x).split(".")[:3]) + ".0/24"
    ).unique().tolist()
    rec.cidr_list = subnets
    rec.reason = f"IP分散在{len(subnets)}个子网，建议使用CIDR规则"
    rec.confidence = 0.6

    return rec
