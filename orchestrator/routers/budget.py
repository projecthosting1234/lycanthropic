"""Budget-conscious alloy router — use expensive models sparingly."""

from __future__ import annotations

from orchestrator.adapters.base import ProviderAdapter
from orchestrator.models import Conversation, Role
from orchestrator.routers.base import AlloyRouter


class BudgetRouter(AlloyRouter):
    """
    Route based on cost budget. Use expensive models sparingly,
    cheap models for routine tool-call loops.

    Useful for long research sessions (50+ tool calls) where you
    don't want every turn going through the premium model.
    """

    def __init__(
        self,
        adapters: dict[str, ProviderAdapter],
        premium_model: str = "claude",
        economy_model: str = "openai",
        *,
        premium_ratio: float = 0.3,
        premium_every_n: int = 5,
    ):
        super().__init__(adapters)
        self.premium_model = premium_model
        self.economy_model = economy_model
        self.premium_ratio = premium_ratio
        self.premium_every_n = premium_every_n
        self._total_calls = 0
        self._premium_calls = 0

        if premium_model not in adapters:
            self.premium_model = list(adapters.keys())[0]
        if economy_model not in adapters:
            self.economy_model = list(adapters.keys())[-1]

    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        self._total_calls += 1
        current_ratio = self._premium_calls / max(self._total_calls, 1)

        # Under budget → allow premium for important turns
        if current_ratio < self.premium_ratio:
            if self._is_important_turn(conversation, turn):
                self._premium_calls += 1
                return self.adapters[self.premium_model]

        return self.adapters[self.economy_model]

    def _is_important_turn(self, conversation: Conversation, turn: int) -> bool:
        """Heuristic: is this a turn where quality matters most?"""
        # First turn — planning
        if turn == 0:
            return True

        # Every Nth turn — periodic premium check-in
        if turn % self.premium_every_n == 0:
            return True

        # Direct user input → premium
        last = conversation.last()
        if last and last.role == Role.USER:
            return True

        return False

    @property
    def budget_usage(self) -> dict:
        return {
            "total_calls": self._total_calls,
            "premium_calls": self._premium_calls,
            "current_ratio": self._premium_calls / max(self._total_calls, 1),
            "target_ratio": self.premium_ratio,
        }
