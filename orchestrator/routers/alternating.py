"""Alternating alloy router — strictly alternate between models in order."""

from __future__ import annotations

from orchestrator.adapters.base import ProviderAdapter
from orchestrator.models import Conversation
from orchestrator.routers.base import AlloyRouter


class AlternatingRouter(AlloyRouter):
    """
    Strictly alternate between models in a fixed order.

    Useful for A/B testing or when you want predictable interleaving.
    """

    def __init__(
        self,
        adapters: dict[str, ProviderAdapter],
        order: list[str] | None = None,
    ):
        super().__init__(adapters)
        self.order = order or list(adapters.keys())
        # Validate all names exist
        for name in self.order:
            if name not in adapters:
                raise ValueError(f"Unknown provider in order: {name}")

    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        idx = turn % len(self.order)
        return self.adapters[self.order[idx]]
