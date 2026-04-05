"""Abstract base for alloy routers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from orchestrator.adapters.base import ProviderAdapter
from orchestrator.models import Conversation


@dataclass
class RouterStats:
    """Tracks router selection history."""

    calls: list[str] = field(default_factory=list)

    def record(self, provider: str) -> None:
        self.calls.append(provider)

    @property
    def total(self) -> int:
        return len(self.calls)

    def breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self.calls:
            counts[p] = counts.get(p, 0) + 1
        return counts

    def ratios(self) -> dict[str, float]:
        if not self.calls:
            return {}
        counts = self.breakdown()
        return {k: v / len(self.calls) for k, v in counts.items()}


class AlloyRouter(ABC):
    """
    Decides which adapter to use for each orchestrator turn.

    This is where the alloying strategy lives. Subclasses implement
    different selection policies.
    """

    def __init__(self, adapters: dict[str, ProviderAdapter]):
        if not adapters:
            raise ValueError("At least one adapter is required")
        self.adapters = adapters
        self.stats = RouterStats()

    @abstractmethod
    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        """Pick which model to call for this turn."""
        ...

    def record(self, provider_name: str) -> None:
        self.stats.record(provider_name)

    @property
    def available_providers(self) -> list[str]:
        return list(self.adapters.keys())
