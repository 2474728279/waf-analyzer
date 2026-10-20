"""规则覆盖率计算器 - 逐条规则精确匹配，计算覆盖率"""

import pandas as pd
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RuleCoverage:
    rule_name: str
    matched_count: int = 0
    attack_types_covered: dict[str, int] = field(default_factory=dict)
    attack_types_expected: list[str] = field(default_factory=list)


def calculate_coverage(
    df: pd.DataFrame,
    rules: list[dict],
) -> tuple[float, pd.DataFrame]:
    """计算规则集的覆盖率。

    Args:
        df: WAF日志DataFrame
        rules: 规则列表，每条规则包含:
            - name: 规则名称
            - pattern_type: "url" | "cidr" | "single_ip"
            - pattern: 匹配条件(dict)
            - disabled_modules: 关闭的检测模块列表
            - attack_types: 该规则覆盖的攻击类型列表

    Returns:
        (覆盖率百分比, 标记了covered列的DataFrame)
    """
    df = df.copy()
    df["_covered"] = False

    for rule in rules:
        mask = _match_rule(df, rule)
        df.loc[mask, "_covered"] = True

    total = len(df)
    covered = df["_covered"].sum()
    coverage_pct = covered / total * 100 if total > 0 else 0

    return coverage_pct, df


def _match_rule(df: pd.DataFrame, rule: dict) -> pd.Series:
    """根据规则定义匹配DataFrame行。"""
    pattern_type = rule.get("pattern_type", "url")
    pattern = rule.get("pattern", {})
    attack_types = rule.get("attack_types", [])

    mask = pd.Series(True, index=df.index)

    if pattern_type == "url":
        # URL模式匹配
        if "urlpath" in pattern:
            url_match = pattern["urlpath"]
            match_type = pattern.get("urlpath_match_type", "infix")
            if match_type == "infix":
                mask &= df["url_path"].str.contains(url_match, na=False)
            elif match_type == "str":
                mask &= df["url_path"] == url_match
            elif match_type == "re":
                mask &= df["url_path"].str.contains(url_match, na=False, regex=True)

        if "host" in pattern:
            host_match = pattern["host"]
            host_type = pattern.get("host_match_type", "infix")
            if host_type == "infix":
                mask &= df["host"].str.contains(host_match, na=False)
            elif host_type == "str":
                mask &= df["host"] == host_match

    elif pattern_type == "cidr":
        cidr_list = pattern.get("cidr_list", [])
        if cidr_list:
            cidr_mask = pd.Series(False, index=df.index)
            for cidr in cidr_list:
                prefix = cidr.replace(".0/24", ".")
                cidr_mask |= df["src_ip"].apply(lambda x: str(x).startswith(prefix))
            mask &= cidr_mask

        if "host" in pattern:
            host_match = pattern["host"]
            host_type = pattern.get("host_match_type", "infix")
            if host_type == "infix":
                mask &= df["host"].str.contains(host_match, na=False)
            elif host_type == "str":
                mask &= df["host"] == host_match

    elif pattern_type == "single_ip":
        ips = pattern.get("ips", [])
        if ips:
            mask &= df["src_ip"].isin(ips)

        if "host" in pattern:
            host_match = pattern["host"]
            host_type = pattern.get("host_match_type", "str")
            if host_type == "str":
                mask &= df["host"] == host_match

    # 攻击类型过滤
    if attack_types:
        mask &= df["attack_type"].isin(attack_types)

    return mask
