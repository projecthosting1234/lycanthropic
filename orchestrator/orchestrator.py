"""
Main orchestrator loop — drives the agent conversation.

Each iteration:
1. Pruner checks if context needs compressing
2. Router picks which model to call
3. Adapter translates and calls the provider API
4. Cache manager records prompt cache stats
5. If the model made tool calls → execute via bridge (with tool result caching)
6. Append results to conversation history
7. Loop until model gives a final text answer or max turns reached
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from orchestrator.bridge import MCPBridge
from orchestrator.cache import CacheManager
from orchestrator.models import Conversation, Message, Role
from orchestrator.pruning import ConversationPruner
from orchestrator.routers.base import AlloyRouter

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Main agent loop tying router, bridge, pruner, and cache together.

    Usage:
        agent = Orchestrator(router, bridge, system_prompt)
        response = await agent.run("Analyze nt!NtCreateFile")
        print(agent.get_stats())
    """

    def __init__(
        self,
        router: AlloyRouter,
        bridge: MCPBridge,
        system_prompt: str,
        *,
        cache: CacheManager | None = None,
        pruner: ConversationPruner | None = None,
        max_turns: int = 100,
        max_consecutive_errors: int = 3,
        on_turn: Callable[[int, str, str], None] | None = None,
        on_tool_call: Callable[[str, str, dict], None] | None = None,
        on_tool_result: Callable[[str, str, bool], None] | None = None,
    ):
        self.router = router
        self.bridge = bridge
        self.cache = cache or bridge.cache
        self.pruner = pruner or ConversationPruner()
        self.max_turns = max_turns
        self.max_consecutive_errors = max_consecutive_errors

        # Callbacks for UI/logging integration
        self._on_turn = on_turn
        self._on_tool_call = on_tool_call
        self._on_tool_result = on_tool_result

        self.conversation = Conversation(system_prompt=system_prompt)
        self.turn = 0

        self._stats = {
            "total_turns": 0,
            "tool_calls": 0,
            "tool_cache_hits": 0,
            "errors": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "provider_breakdown": {},
        }

    async def run(self, user_message: str) -> str:
        """
        Run the agent loop for a user message.
        Returns the final text response.
        """
        self.conversation.append(
            Message(role=Role.USER, content=user_message)
        )

        consecutive_errors = 0

        while self.turn < self.max_turns:
            # 1. Router picks model
            adapter = self.router.select(self.conversation, self.turn)
            self.router.record(adapter.provider_name)

            provider_tag = f"{adapter.provider_name}/{adapter.model_name}"
            logger.info("[Turn %d] Using %s", self.turn, provider_tag)

            if self._on_turn:
                self._on_turn(self.turn, adapter.provider_name, adapter.model_name)

            # 2. Prune conversation if needed (async — may call aux model)
            messages_to_send = await self.pruner.prune(self.conversation)

            # 3. Call the model
            try:
                start = time.monotonic()
                assistant_msg = await adapter.call(
                    system_prompt=self.conversation.system_prompt,
                    messages=messages_to_send,
                    tools=self.bridge.tools,
                )
                assistant_msg.latency_ms = int((time.monotonic() - start) * 1000)
                assistant_msg.timestamp = time.time()
                consecutive_errors = 0

            except Exception as e:
                consecutive_errors += 1
                self._stats["errors"] += 1
                logger.error("[Turn %d] API error: %s", self.turn, e)

                if consecutive_errors >= self.max_consecutive_errors:
                    return (
                        f"Agent stopped after {self.max_consecutive_errors} "
                        f"consecutive API errors. Last error: {e}"
                    )
                continue

            # 4. Record cache stats
            self.cache.record_api_call(
                input_tokens=assistant_msg.tokens_in,
                cache_read=assistant_msg.cache_read_tokens,
                cache_creation=assistant_msg.cache_creation_tokens,
            )

            # 5. Append assistant message to history
            self.conversation.append(assistant_msg)
            self._update_stats(assistant_msg)

            # 6. If no tool calls → final answer
            if not assistant_msg.has_tool_calls:
                return assistant_msg.content or ""

            # 7. Execute tool calls
            logger.info(
                "[Turn %d] Executing %d tool call(s)",
                self.turn,
                len(assistant_msg.tool_calls),
            )

            for tc in assistant_msg.tool_calls:
                if self._on_tool_call:
                    self._on_tool_call(tc.server, tc.tool_name, tc.arguments)
                logger.debug(
                    "  -> %s.%s(%s)",
                    tc.server,
                    tc.tool_name,
                    _summarize_args(tc.arguments),
                )

            results = await self.bridge.execute_tool_calls(assistant_msg.tool_calls)

            # 8. Append tool results to history
            tool_result_msg = Message(
                role=Role.TOOL_RESULT,
                tool_results=results,
            )
            self.conversation.append(tool_result_msg)

            # Log results
            for r in results:
                status = "ERROR" if r.is_error else "OK"
                preview = r.content[:200] + "..." if len(r.content) > 200 else r.content
                logger.debug("  <- [%s] %s", status, preview)
                if self._on_tool_result:
                    self._on_tool_result(r.tool_call_id, preview, r.is_error)

            self.turn += 1
            self._stats["tool_calls"] += len(assistant_msg.tool_calls)

        return "Agent stopped: max turns reached"

    def pin_fact(self, fact: str) -> None:
        """Pin a fact that survives conversation pruning."""
        self.conversation.pinned_facts.append(fact)

    def invalidate_cache(self, event: str = "general") -> None:
        """Signal a state change to invalidate relevant caches."""
        self.cache.on_state_change(event)

    def _update_stats(self, msg: Message) -> None:
        self._stats["total_turns"] += 1
        self._stats["tokens_in"] += msg.tokens_in
        self._stats["tokens_out"] += msg.tokens_out
        provider = msg.provider
        self._stats["provider_breakdown"][provider] = (
            self._stats["provider_breakdown"].get(provider, 0) + 1
        )

    def get_stats(self) -> dict[str, Any]:
        """Full stats including routing breakdown and cache performance."""
        total_turns = max(self._stats["total_turns"], 1)
        return {
            **self._stats,
            "alloy_composition": {
                k: round(v / total_turns, 3)
                for k, v in self._stats["provider_breakdown"].items()
            },
            "router_stats": self.router.stats.ratios(),
            "cache": self.cache.summary(),
        }

    def reset(self) -> None:
        """Reset conversation and turn counter for a new task."""
        self.conversation = Conversation(
            system_prompt=self.conversation.system_prompt,
            metadata=self.conversation.metadata,
        )
        self.turn = 0


def _summarize_args(args: dict, max_len: int = 80) -> str:
    parts: list[str] = []
    for k, v in args.items():
        sv = str(v)
        if len(sv) > 50:
            sv = sv[:50] + "..."
        parts.append(f"{k}={sv}")
    text = ", ".join(parts)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text
