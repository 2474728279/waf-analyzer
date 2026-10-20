from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class ProjectStatus(str, Enum):
    CREATED = "created"
    UPLOADING = "uploading"
    ANALYZING = "analyzing"
    REVIEW = "review"
    DEPLOYING = "deploying"
    COMPLETED = "completed"
    FAILED = "failed"


class ProjectCreate(BaseModel):
    name: str
    customer_name: str
    waf_device_ip: str
    waf_device_name: str = ""
    description: str = ""


class Project(BaseModel):
    id: str
    name: str
    customer_name: str
    waf_device_ip: str
    waf_device_name: str
    description: str
    status: ProjectStatus = ProjectStatus.CREATED
    total_logs: int = 0
    log_file_path: Optional[str] = None
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class WAFDeviceCreate(BaseModel):
    name: str
    vendor: str = "safeline"
    base_url: str
    api_token: str
    verify_ssl: bool = False


class WAFDevice(BaseModel):
    id: str
    name: str
    vendor: str
    base_url: str
    api_token: str
    verify_ssl: bool = False
    created_at: datetime = Field(default_factory=datetime.now)
