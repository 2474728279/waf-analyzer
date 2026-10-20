"""子网聚合模块 - 按/24子网聚合告警，识别业务归属"""

import pandas as pd
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SubnetInfo:
    cidr: str  # e.g. "10.5.73.0/24"
    log_count: int = 0
    ip_count: int = 0
    ip_list: list[str] = field(default_factory=list)
    attack_types: dict[str, int] = field(default_factory=dict)
    target_hosts: dict[str, int] = field(default_factory=dict)
    top_urls: dict[str, int] = field(default_factory=dict)
    business_name: str = ""  # 推断的业务名称
    rule_strategy: str = ""  # 建议的规则策略: "url" | "cidr" | "single_ip"

    @property
    def is_concentrated(self) -> bool:
        """告警是否集中在少数IP（适合单IP规则）"""
        return self.ip_count <= 3

    @property
    def has_single_target(self) -> bool:
        """是否只访问一个目标Host"""
        return len(self.target_hosts) == 1

    @property
    def has_single_url(self) -> bool:
        """是否只访问一种URL模式"""
        return len(self.top_urls) <= 2


def aggregate_subnets(
    df: pd.DataFrame,
    min_count: int = 5,
) -> list[SubnetInfo]:
    """按/24子网聚合告警。

    Args:
        df: WAF日志DataFrame
        min_count: 最小告警数过滤

    Returns:
        子网信息列表，按告警数降序
    """
    df = df.copy()
    df["_subnet"] = df["src_ip"].apply(
        lambda x: ".".join(str(x).split(".")[:3]) + ".0/24"
    )

    results = []
    for subnet, group in df.groupby("_subnet"):
        if len(group) < min_count:
            continue

        info = SubnetInfo(
            cidr=subnet,
            log_count=len(group),
            ip_count=group["src_ip"].nunique(),
            ip_list=group["src_ip"].unique().tolist()[:20],
        )

        if "attack_type" in df.columns:
            info.attack_types = group["attack_type"].value_counts().head(5).to_dict()

        if "host" in df.columns:
            info.target_hosts = group["host"].value_counts().head(5).to_dict()

        if "url_path" in df.columns:
            info.top_urls = group["url_path"].value_counts().head(5).to_dict()

        # 推断规则策略
        if info.is_concentrated and info.has_single_target and info.has_single_url:
            info.rule_strategy = "url"
        elif info.ip_count >= 5:
            info.rule_strategy = "cidr"
        elif info.is_concentrated:
            info.rule_strategy = "single_ip"
        else:
            info.rule_strategy = "cidr"

        results.append(info)

    results.sort(key=lambda x: x.log_count, reverse=True)
    return results


def group_ips_by_business(
    profiles: dict,
    subnets: list[SubnetInfo],
) -> dict[str, list[str]]:
    """按业务系统分组IP。

    基于目标Host和URL模式将IP归入业务分组。
    Returns:
        {业务名称: [ip1, ip2, ...]}
    """
    groups = {}

    for subnet in subnets:
        for host, count in subnet.target_hosts.items():
            if host not in groups:
                groups[host] = []
            groups[host].extend(subnet.ip_list)

    # 去重
    for k in groups:
        groups[k] = list(set(groups[k]))

    return groups
