"""Claude API Provider - Anthropic SDK"""

import anthropic
from app.llm.base import LLMBase, LLMMessage, LLMResponse


class ClaudeProvider(LLMBase):
    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001", **kwargs):
        super().__init__(model, **kwargs)
        self.client = anthropic.AsyncAnthropic(api_key=api_key)

    async def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        system_msg = ""
        chat_msgs = []
        for m in messages:
            if m.role == "system":
                system_msg = m.content
            else:
                chat_msgs.append({"role": m.role, "content": m.content})

        kwargs = {
            "model": self.model,
            "messages": chat_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_msg:
            kwargs["system"] = system_msg

        resp = await self.client.messages.create(**kwargs)

        return LLMResponse(
            content=resp.content[0].text,
            model=resp.model,
            usage={
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
            finish_reason=resp.stop_reason,
        )

    async def close(self):
        await self.client.close()
