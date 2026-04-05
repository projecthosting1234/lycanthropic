"""
Normalized message format for provider-agnostic conversation history.

All provider adapters translate to/from these types. The orchestrator,
routers, and pruner only ever see normalized messages — never raw
provider wire format.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL_RESULT = "tool_result"


@dataclass
class ToolCall:
    """A single tool invocation requested by the model."""

    id: str
    server: str        # MCP server name: "windbg", "ida", "gadget", "sysinternals"
    tool_name: str     # tool name within that server
    arguments: dict[str, Any]

    @staticmethod
    def make_id() -> str:
        return f"tc_{uuid.uuid4().hex[:12]}"


@dataclass
class ToolResult:
    """Result of executing a ToolCall."""

    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class ToolSchema:
    """Normalized MCP tool schema exposed to provider adapters."""

    server: str
    name: str
    description: str
    parameters: dict[str, Any]   # JSON Schema

    @property
    def qualified_name(self) -> str:
        """Globally unique name: server__toolname."""
        return f"{self.server}__{self.name}"


@dataclass
class Message:
    """
    A single normalized message in the conversation.

    - ASSISTANT messages may carry both text content and tool_calls.
    - TOOL_RESULT messages carry one or more ToolResult entries.
    - USER/SYSTEM messages carry text content only.
    """

    role: Role
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)

    # Internal metadata — never sent to any model
    provider: str = ""           # "claude" | "openai"
    model: str = ""              # exact model ID
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read_tokens: int = 0   # tokens served from prompt cache
    cache_creation_tokens: int = 0
    latency_ms: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    def text_length(self) -> int:
        """Rough character count of all payload in this message."""
        n = len(self.content or "")
        for tc in self.tool_calls:
            n += len(str(tc.arguments))
        for tr in self.tool_results:
            n += len(tr.content)
        return n


@dataclass
class Conversation:
    """
    The full conversation state — system prompt + message history.

    This is the single source of truth that the orchestrator mutates
    and the pruner can compress.
    """

    system_prompt: str
    messages: list[Message] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Pinned facts survive pruning — critical offsets, findings, etc.
    pinned_facts: list[str] = field(default_factory=list)

    def append(self, msg: Message) -> None:
        self.messages.append(msg)

    def last(self, role: Role | None = None) -> Message | None:
        """Return the most recent message, optionally filtered by role."""
        for msg in reversed(self.messages):
            if role is None or msg.role == role:
                return msg
        return None

    def estimate_tokens(self) -> int:
        """Rough token estimate: ~4 chars per token."""
        n = len(self.system_prompt) // 4
        for msg in self.messages:
            n += msg.text_length() // 4
        return n

    def turn_count(self) -> int:
        """Number of assistant turns so far."""
        return sum(1 for m in self.messages if m.role == Role.ASSISTANT)
