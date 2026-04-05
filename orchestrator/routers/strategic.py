"""
Strategic alloy routers — pick models based on task characteristics.

The StrategicRouter uses heuristics about the current conversation state
to decide whether to use the "reasoning" model (better at complex analysis)
or the "workhorse" model (faster/cheaper for routine tool-call loops).

The StrategicRouterWithThinking variant adds a third option: the extended
thinking adapter for turns that need deep multi-step reasoning.
"""

from __future__ import annotations

import random

from orchestrator.adapters.base import ProviderAdapter
from orchestrator.models import Conversation, Role
from orchestrator.routers.base import AlloyRouter

# Keywords that suggest a turn needs strong reasoning
REASONING_SIGNALS = frozenset({
    "analyze", "vulnerability", "exploit", "chain",
    "strategy", "plan", "hypothesis", "correlat",
    "irql", "privilege", "bypass", "primitive",
    "root cause", "overflow", "confusion", "race",
    "use-after-free", "arbitrary", "escalat",
})

# Keywords suggesting deep thinking (superset of reasoning for the thinking variant)
THINKING_TRIGGERS = frozenset(REASONING_SIGNALS | {
    "summarize", "compare", "design", "architect",
    "classify", "enumerate all", "comprehensive",
    "correlate", "reconstruct",
})


class StrategicRouter(AlloyRouter):
    """
    Pick model based on task characteristics.

    Routing heuristics for kernel research:
    - Complex reasoning / exploit chain planning → reasoning_model
    - Bulk struct parsing / routine tool calls → workhorse_model
    - First turn (planning) → always reasoning_model
    - Large tool output to analyze → reasoning_model
    """

    def __init__(
        self,
        adapters: dict[str, ProviderAdapter],
        reasoning_model: str = "claude",
        workhorse_model: str = "openai",
        *,
        workhorse_bias: float = 0.6,
    ):
        super().__init__(adapters)
        self.reasoning_model = reasoning_model
        self.workhorse_model = workhorse_model
        self.workhorse_bias = workhorse_bias

        # Fall back if configured model isn't available
        if reasoning_model not in adapters:
            self.reasoning_model = list(adapters.keys())[0]
        if workhorse_model not in adapters:
            self.workhorse_model = list(adapters.keys())[-1]

    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        # First turn: always use reasoning model to plan
        if turn == 0:
            return self.adapters[self.reasoning_model]

        # Check if recent tool results are large (needs reasoning to analyze)
        if self._has_large_recent_output(conversation):
            return self.adapters[self.reasoning_model]

        # Check for reasoning signals in recent conversation
        if self._has_reasoning_signals(conversation):
            return self.adapters[self.reasoning_model]

        # Default: biased toward workhorse for routine work
        if random.random() < self.workhorse_bias:
            return self.adapters[self.workhorse_model]
        return self.adapters[self.reasoning_model]

    def _has_large_recent_output(
        self,
        conversation: Conversation,
        threshold: int = 5000,
    ) -> bool:
        """Check if recent tool results contain lots of data to analyze."""
        last = conversation.last(Role.TOOL_RESULT)
        if last and last.tool_results:
            total = sum(len(tr.content) for tr in last.tool_results)
            return total > threshold
        return False

    def _has_reasoning_signals(self, conversation: Conversation) -> bool:
        """Check if recent messages contain keywords that need reasoning."""
        # Check last assistant message
        last_assistant = conversation.last(Role.ASSISTANT)
        if last_assistant and last_assistant.content:
            text = last_assistant.content.lower()
            if any(s in text for s in REASONING_SIGNALS):
                return True

        # Check last user message
        last_user = conversation.last(Role.USER)
        if last_user and last_user.content:
            text = last_user.content.lower()
            if any(s in text for s in REASONING_SIGNALS):
                return True

        return False


class StrategicRouterWithThinking(StrategicRouter):
    """
    Enhanced strategic router that includes an extended-thinking adapter
    for turns that need deep multi-step reasoning.

    Three tiers:
    1. thinking_adapter — complex analysis, exploit design, large data correlation
    2. reasoning_model — moderate reasoning, planning, follow-up analysis
    3. workhorse_model — routine tool calls, simple follow-ups
    """

    def __init__(
        self,
        adapters: dict[str, ProviderAdapter],
        thinking_adapter: ProviderAdapter,
        reasoning_model: str = "claude",
        workhorse_model: str = "openai",
        *,
        workhorse_bias: float = 0.6,
    ):
        super().__init__(
            adapters,
            reasoning_model=reasoning_model,
            workhorse_model=workhorse_model,
            workhorse_bias=workhorse_bias,
        )
        self.thinking_adapter = thinking_adapter

    def select(self, conversation: Conversation, turn: int) -> ProviderAdapter:
        if self._needs_deep_thinking(conversation):
            return self.thinking_adapter
        return super().select(conversation, turn)

    def _needs_deep_thinking(self, conversation: Conversation) -> bool:
        """Determine if this turn warrants extended thinking."""
        if not conversation.messages:
            return False

        # Large tool output + reasoning signals → deep thinking
        large_output = self._has_large_recent_output(conversation, threshold=10000)
        if large_output:
            return True

        # Check user message for thinking triggers
        last_user = conversation.last(Role.USER)
        if last_user and last_user.content:
            text = last_user.content.lower()
            if any(t in text for t in THINKING_TRIGGERS):
                return True

        return False
