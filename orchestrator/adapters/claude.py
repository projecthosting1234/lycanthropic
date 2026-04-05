"""
Anthropic Claude adapter with prompt caching support.

Prompt caching strategy:
- System prompt blocks get cache_control: {"type": "ephemeral"} so the
  large kernel-knowledge system prompt is cached across turns.
- Tool definitions get a cache breakpoint on the last tool, caching the
  entire tool schema block.
- The first few static messages (original user task) can be cached too
  if they remain unchanged across turns.

This saves re-tokenizing ~50K+ tokens of system prompt + tools on every
single turn, cutting input costs significantly.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import anthropic

from orchestrator.adapters.base import AuxiliaryAdapter, ProviderAdapter
from orchestrator.models import Message, Role, ToolCall, ToolResult, ToolSchema

logger = logging.getLogger(__name__)


class ClaudeAdapter(ProviderAdapter):
    """
    Standard Claude adapter with Anthropic prompt caching.

    Uses cache_control breakpoints on system prompt and tool definitions
    to minimize re-tokenization costs across turns.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-4-6-20250514",
        *,
        enable_prompt_cache: bool = True,
    ):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model
        self.enable_prompt_cache = enable_prompt_cache

    async def call(
        self,
        system_prompt: str,
        messages: list[Message],
        tools: list[ToolSchema],
        *,
        temperature: float = 0.0,
        max_tokens: int = 16384,
    ) -> Message:
        system_blocks = self._build_system(system_prompt)
        api_messages = self._translate_messages(messages)
        api_tools = self.translate_tools(tools)

        start = time.monotonic()
        response = await self.client.messages.create(
            model=self.model,
            system=system_blocks,
            messages=api_messages,
            tools=api_tools,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        latency = int((time.monotonic() - start) * 1000)

        return self._parse_response(response, latency)

    # ------------------------------------------------------------------
    # System prompt with caching
    # ------------------------------------------------------------------

    def _build_system(self, system_prompt: str) -> list[dict]:
        """
        Build system prompt blocks with cache_control.

        We split the system prompt into a single text block and mark it
        for caching. On subsequent turns the entire block is served from
        cache, saving input token costs.
        """
        block: dict[str, Any] = {
            "type": "text",
            "text": system_prompt,
        }
        if self.enable_prompt_cache:
            block["cache_control"] = {"type": "ephemeral"}
        return [block]

    # ------------------------------------------------------------------
    # Message translation: normalized → Anthropic wire format
    # ------------------------------------------------------------------

    def _translate_messages(self, messages: list[Message]) -> list[dict]:
        api_messages: list[dict] = []

        for msg in messages:
            if msg.role == Role.USER:
                api_messages.append({"role": "user", "content": msg.content or ""})

            elif msg.role == Role.ASSISTANT:
                content: list[dict] = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": f"{tc.server}__{tc.tool_name}",
                        "input": tc.arguments,
                    })
                api_messages.append({"role": "assistant", "content": content})

            elif msg.role == Role.TOOL_RESULT:
                api_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tr.tool_call_id,
                            "content": tr.content,
                            "is_error": tr.is_error,
                        }
                        for tr in msg.tool_results
                    ],
                })

        # Apply cache breakpoint to the last user message in the prefix
        # so the stable conversation prefix is cached across turns.
        if self.enable_prompt_cache:
            self._apply_message_cache_breakpoints(api_messages)

        return api_messages

    def _apply_message_cache_breakpoints(self, api_messages: list[dict]) -> None:
        """
        Mark the last content block of the second-to-last user message
        with cache_control. This caches the stable prefix of the
        conversation — everything before the latest tool results.

        Cache breakpoint placement strategy:
        - The system prompt is always cached (see _build_system).
        - We add a breakpoint on the penultimate user/tool_result turn,
          so only the newest exchange is re-tokenized each turn.
        """
        user_indices = [
            i for i, m in enumerate(api_messages) if m["role"] == "user"
        ]
        if len(user_indices) >= 2:
            target_idx = user_indices[-2]
            target_msg = api_messages[target_idx]
            content = target_msg["content"]
            if isinstance(content, list) and content:
                content[-1]["cache_control"] = {"type": "ephemeral"}
            elif isinstance(content, str):
                # Convert to block format to add cache_control
                api_messages[target_idx]["content"] = [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]

    # ------------------------------------------------------------------
    # Tool schema translation
    # ------------------------------------------------------------------

    def translate_tools(self, tools: list[ToolSchema]) -> list[dict]:
        api_tools = [
            {
                "name": t.qualified_name,
                "description": t.description,
                "input_schema": t.parameters,
            }
            for t in tools
        ]
        # Cache breakpoint on last tool — caches entire tool block
        if self.enable_prompt_cache and api_tools:
            api_tools[-1]["cache_control"] = {"type": "ephemeral"}
        return api_tools

    # ------------------------------------------------------------------
    # Response parsing: Anthropic → normalized
    # ------------------------------------------------------------------

    def _parse_response(self, response: Any, latency_ms: int) -> Message:
        msg = Message(
            role=Role.ASSISTANT,
            provider="claude",
            model=self.model,
            latency_ms=latency_ms,
        )

        for block in response.content:
            if block.type == "text":
                msg.content = (msg.content or "") + block.text
            elif block.type == "tool_use":
                server, tool = self._split_tool_name(block.name)
                msg.tool_calls.append(ToolCall(
                    id=block.id,
                    server=server,
                    tool_name=tool,
                    arguments=block.input,
                ))

        # Token usage
        usage = response.usage
        msg.tokens_in = usage.input_tokens
        msg.tokens_out = usage.output_tokens
        msg.cache_read_tokens = getattr(usage, "cache_read_input_tokens", 0) or 0
        msg.cache_creation_tokens = getattr(usage, "cache_creation_input_tokens", 0) or 0

        if msg.cache_read_tokens:
            logger.debug(
                "Prompt cache hit: %d tokens read from cache, %d created",
                msg.cache_read_tokens,
                msg.cache_creation_tokens,
            )

        return msg

    @staticmethod
    def _split_tool_name(qualified: str) -> tuple[str, str]:
        """Split 'server__toolname' → (server, toolname)."""
        parts = qualified.split("__", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return "", qualified

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return self.model


class ClaudeExtendedAdapter(ClaudeAdapter):
    """
    Claude adapter with extended thinking enabled.

    Use for complex turns: exploit chain planning, vulnerability analysis,
    correlating large disassembly outputs. Extended thinking gives the
    model a scratchpad for multi-step reasoning before responding.

    Costs more (thinking tokens are billed) and adds latency — the
    StrategicRouter activates this only when deep reasoning is needed.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-4-6-20250514",
        *,
        thinking_budget: int = 32768,
        enable_prompt_cache: bool = True,
    ):
        super().__init__(
            api_key=api_key,
            model=model,
            enable_prompt_cache=enable_prompt_cache,
        )
        self.thinking_budget = thinking_budget

    async def call(
        self,
        system_prompt: str,
        messages: list[Message],
        tools: list[ToolSchema],
        *,
        temperature: float = 1.0,  # required for extended thinking
        max_tokens: int = 16384,
    ) -> Message:
        system_blocks = self._build_system(system_prompt)
        api_messages = self._translate_messages(messages)
        api_tools = self.translate_tools(tools)

        start = time.monotonic()
        response = await self.client.messages.create(
            model=self.model,
            system=system_blocks,
            messages=api_messages,
            tools=api_tools,
            max_tokens=max_tokens,
            temperature=1.0,  # must be 1.0 for thinking
            thinking={
                "type": "enabled",
                "budget_tokens": self.thinking_budget,
            },
        )
        latency = int((time.monotonic() - start) * 1000)

        msg = self._parse_response(response, latency)
        msg.model = f"{self.model}+thinking"
        return msg


class ClaudeAuxAdapter(AuxiliaryAdapter):
    """
    Cheap, fast Claude adapter for auxiliary tasks.

    Uses Haiku for conversation summarization, fact extraction,
    classification, and other non-task-execution work. Never sees
    tools — just text in, text out.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-haiku-4-5-20251001",
    ):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            kwargs["system"] = system

        response = await self.client.messages.create(**kwargs)

        parts: list[str] = []
        for block in response.content:
            if block.type == "text":
                parts.append(block.text)
        return "".join(parts)

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return self.model
