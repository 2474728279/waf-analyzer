"""LLM抽象基类 - 定义统一调用接口"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: dict = field(default_factory=dict)
    finish_reason: Optional[str] = None


class LLMBase(ABC):
    """LLM Provider抽象基类。"""

    def __init__(self, model: str, **kwargs):
        self.model = model

    @abstractmethod
    async def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """发送对话请求。"""

    @abstractmethod
    async def close(self):
        """关闭连接。"""

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> str:
        """便捷方法：system+user两轮对话，返回文本内容。"""
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt),
        ]
        resp = await self.chat(messages, temperature=temperature, max_tokens=max_tokens)
        return resp.content
