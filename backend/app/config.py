from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "WAF日志分析智能体"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    DATABASE_URL: str = "postgresql+asyncpg://wafagent:wafagent@localhost:5432/wafagent"
    REDIS_URL: str = "redis://localhost:6379/0"

    LLM_PROVIDER: str = "claude"
    ANTHROPIC_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    LLM_MODEL_FAST: str = "claude-haiku-4-5-20251001"
    LLM_MODEL_SMART: str = "claude-sonnet-4-20250514"

    UPLOAD_DIR: str = "/tmp/waf-agent/uploads"
    REPORT_DIR: str = "/tmp/waf-agent/reports"

    class Config:
        env_file = ".env"
        env_prefix = "WAF_"


settings = Settings()
