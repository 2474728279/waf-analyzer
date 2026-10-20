from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Any


class RuleAction(str, Enum):
    DENY = "deny"
    ALLOW = "allow"
    FORBID = "forbid"
    MODIFY_MODULE = "modify_module"


class RuleStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEPLOYED = "deployED"
    DISABLED = "disabled"


class MatchType(str, Enum):
    INFIX = "infix"
    STR = "str"
    RE = "re"
    CIDR = "cidr"


class MatchField(str, Enum):
    URLPATH = "urlpath"
    HOST = "host"
    REMOTE_ADDR = "remote_addr"
    DECODED_PATH = "decoded_path"
    DECODED_QUERY = "decoded_query"
    QUERY = "query"
    METHOD = "method"
    COOKIE_RAW = "cookie_raw"
    USER_AGENT = "user_agent"
    X_FORWARDED_FOR = "x_forwarded_for"
    ORIGIN = "origin"
    REQUEST_HEADER = "request_header"
    CONTENT_TYPE = "content_type"
    RESPONSE_BODY = "response_body"


class PatternCondition(BaseModel):
    match_type: MatchType
    field: MatchField
    value: str
    decode_methods: list[str] = []


class PatternLogical(BaseModel):
    operator: str  # $AND, $OR, $NOT
    conditions: list[Any]  # PatternCondition or PatternLogical


class ModuleManagement(BaseModel):
    disabled: list[str] = []
    enabled: list[str] = []


class ProposedRule(BaseModel):
    id: Optional[str] = None
    name: str
    comment: str
    action: RuleAction = RuleAction.MODIFY_MODULE
    pattern: dict  # SafeLine pattern DSL
    module_management: ModuleManagement
    is_enabled: bool = False
    is_global: bool = False
    status: RuleStatus = RuleStatus.PROPOSED
    coverage_count: int = 0
    coverage_percentage: float = 0.0
    description: str = ""
    root_cause: str = ""
    affected_business: str = ""


class WAFRule(BaseModel):
    id: int
    name: str
    comment: str
    action: str
    pattern: dict
    module_management: ModuleManagement
    is_enabled: bool
    is_global: bool = False
    attack_type: int = -1
    websites: list[int] = []
