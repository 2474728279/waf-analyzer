from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class DeployStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeployResult(BaseModel):
    rule_id: str
    rule_name: str
    waf_rule_id: Optional[int] = None
    status: DeployStatus
    message: str = ""
    deployed_at: Optional[datetime] = None


class Deployment(BaseModel):
    id: str
    project_id: str
    waf_device_id: str
    rule_ids: list[str]
    results: list[DeployResult] = []
    status: DeployStatus = DeployStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.now)
