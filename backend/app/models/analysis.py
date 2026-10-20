from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class AttackType(str, Enum):
    SCANNER = "扫描器"
    SQL_INJECTION = "SQL 注入"
    DIR_TRAVERSAL = "目录穿越"
    INFO_LEAK = "信息泄露"
    CMD_INJECTION = "命令注入"
    FILE_INCLUDE = "文件包含"
    CODE_INJECTION = "代码注入"
    XSS = "XSS"
    SSRF = "SSRF"
    TIMEOUT = "超时"
    LDAP_INJECTION = "LDAP 注入"
    CODE_EXEC = "代码执行"
    FILE_UPLOAD = "文件上传"
    XXE = "XXE"
    DESERIALIZATION = "反序列化"
    UNAUTHORIZED = "未授权访问"


class RootCauseCategory(str, Enum):
    SQL_INJECTION_FP = "SQL注入误报"
    DIR_TRAVERSAL_FP = "目录穿越误报"
    INFO_LEAK_FP = "信息泄露误报"
    XSS_FP = "XSS误报"
    CMD_INJECTION_FP = "命令注入误报"
    FILE_INCLUDE_FP = "文件包含误报"
    SSRF_FP = "SSRF误报"
    LDAP_INJECTION_FP = "LDAP注入误报"
    SCANNER_MISJUDGE = "扫描器误判"
    VULN_SCANNER = "内网漏扫器"
    NON_BUSINESS = "非业务流量"


class ScannerProfile(BaseModel):
    ip: str
    score: float
    is_scanner: bool
    ua_count: int
    ua_list: list[str] = []
    scanner_ua_ratio: float = 0.0
    url_diversity: float = 0.0
    request_count: int = 0
    target_hosts: list[str] = []
    attack_types: dict[str, int] = {}
    decision_rules_triggered: list[str] = []


class RootCause(BaseModel):
    category: RootCauseCategory
    log_count: int
    percentage: float
    description: str
    affected_ips: list[str] = []
    affected_hosts: list[str] = []
    sample_urls: list[str] = []


class AttackTypeDistribution(BaseModel):
    attack_type: str
    count: int
    percentage: float


class AnalysisOverview(BaseModel):
    total_logs: int = 0
    all_internal: bool = True
    attack_type_distribution: list[AttackTypeDistribution] = []
    scanner_log_count: int = 0
    scanner_ip_count: int = 0
    non_scanner_log_count: int = 0
    root_causes: list[RootCause] = []
    current_coverage: float = 0.0
