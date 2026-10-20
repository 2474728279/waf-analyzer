"""LLM Provider工厂 - 根据配置创建对应的Provider实例"""

from app.config import settings
from app.llm.base import LLMBase


def get_llm(model_tier: str = "fast") -> LLMBase:
    """获取LLM实例。

    Args:
        model_tier: "fast" 使用快速模型, "smart" 使用高能力模型
    """
    provider = settings.LLM_PROVIDER.lower()

    if provider == "claude":
        from app.llm.claude import ClaudeProvider

        api_key = settings.ANTHROPIC_API_KEY
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY未配置")

        model = settings.LLM_MODEL_SMART if model_tier == "smart" else settings.LLM_MODEL_FAST
        return ClaudeProvider(api_key=api_key, model=model)

    elif provider == "openai":
        from app.llm.openai import OpenAIProvider

        api_key = settings.OPENAI_API_KEY
        if not api_key:
            raise ValueError("OPENAI_API_KEY未配置")

        model = "gpt-4o" if model_tier == "smart" else "gpt-4o-mini"
        return OpenAIProvider(api_key=api_key, model=model)

    elif provider == "ollama":
        from app.llm.ollama import OllamaProvider

        model = "qwen2.5:32b" if model_tier == "smart" else "qwen2.5:7b"
        return OllamaProvider(model=model, base_url=settings.OLLAMA_BASE_URL)

    else:
        raise ValueError(f"不支持的LLM Provider: {provider}")
