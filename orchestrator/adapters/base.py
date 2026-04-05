"""Abstract base for LLM provider adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from orchestrator.models import Message, ToolSchema


class ProviderAdapter(ABC):
    """
    Translates between normalized messages and a specific provider's API.

    Contract: take normalized in, return normalized out, hide all provider quirks.
    Used for **task execution** — the big, smart models.
    """

    @abstractmethod
    async def call(
        self,
        system_prompt: str,
        messages: list[Message],
        tools: list[ToolSchema],
        *,
        temperature: float = 0.0,
        max_tokens: int = 16384,
    ) -> Message:
        """Send conversation to the model, return assistant message in normalized format."""
        ...

    @abstractmethod
    def translate_tools(self, tools: list[ToolSchema]) -> list[dict]:
        """Convert normalized MCP tool schemas to provider-specific format."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.provider_name}/{self.model_name})"


class AuxiliaryAdapter(ABC):
    """
    Lightweight adapter for auxiliary tasks — no tools, just text in/out.

    Used for cheap, fast operations that don't need the full task-execution
    model: conversation summarization during pruning, classification for
    routing decisions, fact extraction, etc.

    Implementations should use small models (Haiku, gpt-4.1-mini, etc.).
    """

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        """Simple text completion — no tools, no history, just prompt → response."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.provider_name}/{self.model_name})"
