"""Ollama本地模型Provider"""

import httpx
import json
from app.llm.base import LLMBase, LLMMessage, LLMResponse


class OllamaProvider(LLMBase):
    def __init__(self, model: str = "qwen2.5:7b", base_url: str = "http://localhost:11434", **kwargs):
        super().__init__(model, **kwargs)
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=120.0)

    async def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Ollama chat API
        chat_msgs = [{"role": m.role, "content": m.content} for m in messages]

        payload = {
            "model": self.model,
            "messages": chat_msgs,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        resp = await self.client.post(
            f"{self.base_url}/api/chat",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

        return LLMResponse(
            content=data.get("message", {}).get("content", ""),
            model=data.get("model", self.model),
            usage={
                "input_tokens": data.get("prompt_eval_count", 0),
                "output_tokens": data.get("eval_count", 0),
            },
            finish_reason="stop" if data.get("done") else None,
        )

    async def close(self):
        await self.client.aclose()
