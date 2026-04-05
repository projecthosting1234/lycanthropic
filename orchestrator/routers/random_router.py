"""Random alloy router — pick a model each turn by weighted random selection."""

from __future__ import annotations

import random

from orchestrator.adapters.base import ProviderAdapter
from orchestrator.models import Conversation
from orchestrator.routers.base import AlloyRouter


class RandomRouter(AlloyRouter):
    """
    Randomly pick a model each turn with configurable weights.

    Simplest alloy strategy. Good baseline and fallback for
    single-provider setups (weight=1.0 on the only provider).
    """

    def __init__(
        self,
        adapters: dict[str, ProviderAdapter],
        weights: dict[str, float] | None = None,
    ):
        super().__init__(adapters)
        self.weights = weights or {k: 1.0 for k in adapters}

    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        names = list(self.adapters.keys())
        w = [self.weights.get(n, 1.0) for n in names]
        chosen = random.choices(names, weights=w, k=1)[0]
        return self.adapters[chosen]
