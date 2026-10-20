"""OpenAI API Provider"""

from openai import AsyncOpenAI
from app.llm.base import LLMBase, LLMMessage, LLMResponse


class OpenAIProvider(LLMBase):
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(model, **kwargs)
        client_kwargs = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self.client = AsyncOpenAI(**client_kwargs)

    async def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        chat_msgs = [{"role": m.role, "content": m.content} for m in messages]

        resp = await self.client.chat.completions.create(
            model=self.model,
            messages=chat_msgs,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        choice = resp.choices[0]
        return LLMResponse(
            content=choice.message.content,
            model=resp.model,
            usage={
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
            },
            finish_reason=choice.finish_reason,
        )

    async def close(self):
        await self.client.close()


from typing import Optional  # noqa: E402
