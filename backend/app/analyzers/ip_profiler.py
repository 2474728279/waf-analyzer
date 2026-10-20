"""IP画像模块 - 分析源IP的行为特征"""

import pandas as pd
import re
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class IPProfile:
    ip: str
    request_count: int = 0
    ua_list: list[str] = field(default_factory=list)
    target_hosts: list[str] = field(default_factory=list)
    target_host_counts: dict[str, int] = field(default_factory=dict)
    attack_types: dict[str, int] = field(default_factory=dict)
    url_diversity: float = 0.0
    top_urls: list[str] = field(default_factory=list)
    subnet_24: str = ""
    is_internal: bool = True
    business_group: str = ""  # 归属业务分组

    @property
    def ua_summary(self) -> str:
        if not self.ua_list:
            return "未知"
        if len(self.ua_list) == 1:
            return self.ua_list[0][:60]
        return f"{len(self.ua_list)}种UA"

    @property
    def primary_attack_type(self) -> str:
        if not self.attack_types:
            return ""
        return max(self.attack_types, key=self.attack_types.get)


def _extract_ua(req_header: str) -> str:
    if not isinstance(req_header, str):
        return ""
    match = re.search(r'User-Agent:\s*(.+)', req_header)
    return match.group(1).strip()[:200] if match else ""


def profile_ips(df: pd.DataFrame) -> dict[str, IPProfile]:
    """对DataFrame中的每个源IP生成画像。"""
    profiles = {}

    for ip, group in df.groupby("src_ip"):
        p = IPProfile(ip=ip, request_count=len(group))

        # 子网
        parts = str(ip).split(".")
        if len(parts) == 4:
            p.subnet_24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            p.is_internal = parts[0] in ("10", "172", "192")

        # UA
        if "req_header" in df.columns:
            uas = group["req_header"].apply(_extract_ua)
            p.ua_list = uas[uas != ""].unique().tolist()[:20]

        # 目标Host
        if "host" in df.columns:
            p.target_host_counts = group["host"].value_counts().head(10).to_dict()
            p.target_hosts = list(p.target_host_counts.keys())

        # 攻击类型
        if "attack_type" in df.columns:
            p.attack_types = group["attack_type"].value_counts().head(10).to_dict()

        # URL多样性
        if "url_path" in df.columns:
            p.url_diversity = group["url_path"].nunique() / len(group) if len(group) > 0 else 0
            p.top_urls = group["url_path"].value_counts().head(10).index.tolist()

        profiles[ip] = p

    return profiles
