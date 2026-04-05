"""
OpenAI adapter with prefix-stability optimizations for automatic caching.

OpenAI's API automatically caches the longest common prefix of messages
across requests. To maximize cache hits:
- System message is always first and stays identical.
- Tool definitions stay in the same order.
- Message history only appends — never reorders existing entries.
- We avoid mutating older messages in the history.

These are "free" optimizations — OpenAI doesn't charge extra for cached
prefix tokens and there's no explicit API to control caching.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import openai

from orchestrator.adapters.base import AuxiliaryAdapter, ProviderAdapter
from orchestrator.models import Message, Role, ToolCall, ToolResult, ToolSchema

logger = logging.getLogger(__name__)


class OpenAIAdapter(ProviderAdapter):
    """
    OpenAI chat completions adapter.

    Translates normalized messages to OpenAI wire format and back.
    Relies on OpenAI's automatic prefix caching — we just need to keep
    the message prefix stable across turns.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4.1-2025-04-14",
        *,
        base_url: str | None = None,
    ):
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = openai.AsyncOpenAI(**kwargs)
        self.model = model

    async def call(
        self,
        system_prompt: str,
        messages: list[Message],
        tools: list[ToolSchema],
        *,
        temperature: float = 0.0,
        max_tokens: int = 16384,
    ) -> Message:
        api_messages = self._translate_messages(system_prompt, messages)
        api_tools = self.translate_tools(tools)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if api_tools:
            kwargs["tools"] = api_tools

        start = time.monotonic()
        response = await self.client.chat.completions.create(**kwargs)
        latency = int((time.monotonic() - start) * 1000)

        return self._parse_response(response, latency)

    # ------------------------------------------------------------------
    # Message translation: normalized → OpenAI wire format
    # ------------------------------------------------------------------

    def _translate_messages(
        self,
        system_prompt: str,
        messages: list[Message],
    ) -> list[dict]:
        # System message first — this anchors the cache prefix
        api_messages: list[dict] = [
            {"role": "system", "content": system_prompt}
        ]

        for msg in messages:
            if msg.role == Role.USER:
                api_messages.append({
                    "role": "user",
                    "content": msg.content or "",
                })

            elif msg.role == Role.ASSISTANT:
                oai_msg: dict[str, Any] = {"role": "assistant"}
                if msg.content:
                    oai_msg["content"] = msg.content
                if msg.tool_calls:
                    oai_msg["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": f"{tc.server}__{tc.tool_name}",
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                api_messages.append(oai_msg)

            elif msg.role == Role.TOOL_RESULT:
                # OpenAI expects one "tool" message per tool result
                for tr in msg.tool_results:
                    api_messages.append({
                        "role": "tool",
                        "tool_call_id": tr.tool_call_id,
                        "content": tr.content,
                    })

        return api_messages

    # ------------------------------------------------------------------
    # Tool schema translation
    # ------------------------------------------------------------------

    def translate_tools(self, tools: list[ToolSchema]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.qualified_name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    # ------------------------------------------------------------------
    # Response parsing: OpenAI → normalized
    # ------------------------------------------------------------------

    def _parse_response(self, response: Any, latency_ms: int) -> Message:
        choice = response.choices[0].message
        msg = Message(
            role=Role.ASSISTANT,
            provider="openai",
            model=self.model,
            latency_ms=latency_ms,
        )

        msg.content = choice.content

        if choice.tool_calls:
            for tc in choice.tool_calls:
                server, tool = self._split_tool_name(tc.function.name)
                msg.tool_calls.append(ToolCall(
                    id=tc.id,
                    server=server,
                    tool_name=tool,
                    arguments=json.loads(tc.function.arguments),
                ))

        # Token usage
        usage = response.usage
        msg.tokens_in = usage.prompt_tokens
        msg.tokens_out = usage.completion_tokens

        # OpenAI reports cached tokens in prompt_tokens_details
        details = getattr(usage, "prompt_tokens_details", None)
        if details:
            msg.cache_read_tokens = getattr(details, "cached_tokens", 0) or 0

        if msg.cache_read_tokens:
            logger.debug(
                "OpenAI prefix cache hit: %d tokens cached",
                msg.cache_read_tokens,
            )

        return msg

    @staticmethod
    def _split_tool_name(qualified: str) -> tuple[str, str]:
        parts = qualified.split("__", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return "", qualified

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self.model


class OpenAIAuxAdapter(AuxiliaryAdapter):
    """
    Cheap, fast OpenAI adapter for auxiliary tasks.

    Uses gpt-4.1-mini for conversation summarization, fact extraction,
    classification, and other non-task-execution work. No tools.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4.1-mini-2025-04-14",
        *,
        base_url: str | None = None,
    ):
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = openai.AsyncOpenAI(**kwargs)
        self.model = model

    async def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return response.choices[0].message.content or ""

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self.model
