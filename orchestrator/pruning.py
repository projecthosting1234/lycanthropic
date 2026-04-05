"""
Conversation pruning for long research sessions.

Kernel research sessions can go 100+ turns with large disassembly outputs
and struct dumps. This module manages context window limits by:

1. Keeping the original user task (first message) intact
2. Injecting pinned facts (offsets, key findings) that survive pruning
3. Using a **small auxiliary model** to summarize pruned-away conversation
4. Keeping the most recent N exchanges in full detail

The auxiliary model (Haiku / gpt-4.1-mini) handles summarization —
big models are reserved for actual task execution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from orchestrator.adapters.base import AuxiliaryAdapter
from orchestrator.models import Conversation, Message, Role, ToolResult

logger = logging.getLogger(__name__)

_SUMMARIZE_SYSTEM = (
    "You are a concise research session summarizer. You receive a log of "
    "tool calls, results, and analysis from a Windows kernel security "
    "research session. Produce a dense, factual summary that preserves:\n"
    "- Key offsets, addresses, and struct field values discovered\n"
    "- Functions analyzed and their classifications\n"
    "- Vulnerabilities or security-relevant findings\n"
    "- Build/version information\n"
    "- Any conclusions or hypotheses stated\n\n"
    "Be terse. Use bullet points. No filler. Every line should carry information."
)


@dataclass
class PrunerConfig:
    """Configuration for conversation pruning."""

    max_context_tokens: int = 180_000
    recent_turns_to_keep: int = 20
    max_tool_result_chars: int = 8000
    summary_action_limit: int = 40
    # Max chars of conversation to feed to the aux model for summarization
    aux_summary_input_limit: int = 60_000


class ConversationPruner:
    """
    Manages conversation history to stay within token limits.

    Uses a small auxiliary model for summarization when pruning is needed.
    If no aux model is provided, falls back to naive text extraction.

    Pruning is done on a copy — the original conversation is not mutated.
    """

    def __init__(
        self,
        config: PrunerConfig | None = None,
        aux_model: AuxiliaryAdapter | None = None,
    ):
        self.config = config or PrunerConfig()
        self.aux_model = aux_model

    async def prune(self, conversation: Conversation) -> list[Message]:
        """
        Return a pruned message list that fits in context.

        Does NOT mutate the conversation — returns a new list.
        """
        messages = conversation.messages

        if not messages:
            return []

        est_tokens = conversation.estimate_tokens()
        if est_tokens <= self.config.max_context_tokens:
            return self._truncate_tool_results(messages)

        logger.info(
            "Pruning conversation: ~%d tokens > %d limit, %d messages",
            est_tokens,
            self.config.max_context_tokens,
            len(messages),
        )

        # Split into: first message | middle | recent
        first_msg = messages[0]
        keep_count = min(self.config.recent_turns_to_keep * 2, len(messages) - 1)
        recent = messages[-keep_count:] if keep_count > 0 else []
        middle = messages[1:-keep_count] if keep_count < len(messages) - 1 else []

        # Build pinned facts injection
        pinned = conversation.pinned_facts
        facts_text = ""
        if pinned:
            facts_text = "**Established facts (from prior analysis):**\n"
            facts_text += "\n".join(f"- {f}" for f in pinned)
            facts_text += "\n\n"

        # Summarize middle — use aux model if available, else naive
        if self.aux_model and middle:
            summary = await self._summarize_with_model(middle)
        else:
            summary = self._summarize_naive(middle)

        context_msg = Message(
            role=Role.USER,
            content=(
                f"{facts_text}"
                f"**Summary of prior work ({len(middle)} messages compressed):**\n"
                f"{summary}"
            ),
        )

        pruned = [first_msg, context_msg] + self._truncate_tool_results(recent)

        new_tokens = sum(m.text_length() for m in pruned) // 4
        logger.info(
            "Pruned: %d messages -> %d messages, ~%d tokens -> ~%d tokens",
            len(messages),
            len(pruned),
            est_tokens,
            new_tokens,
        )

        return pruned

    async def _summarize_with_model(self, messages: list[Message]) -> str:
        """
        Use the auxiliary small model to produce a dense summary of
        the pruned-away conversation middle.
        """
        # Build a text log of the middle conversation for the aux model
        log_parts: list[str] = []
        char_budget = self.config.aux_summary_input_limit

        for msg in messages:
            if msg.role == Role.ASSISTANT:
                for tc in msg.tool_calls:
                    args_str = _summarize_args(tc.arguments, max_len=120)
                    log_parts.append(f"[CALL] {tc.server}.{tc.tool_name}({args_str})")
                if msg.content:
                    # Keep first ~300 chars of analysis
                    text = msg.content[:300]
                    log_parts.append(f"[ANALYSIS] {text}")

            elif msg.role == Role.TOOL_RESULT:
                for tr in msg.tool_results:
                    tag = "ERROR" if tr.is_error else "RESULT"
                    # Keep first ~500 chars of each result
                    text = tr.content[:500]
                    log_parts.append(f"[{tag}] {text}")

            elif msg.role == Role.USER:
                if msg.content:
                    log_parts.append(f"[USER] {msg.content[:200]}")

        raw_log = "\n".join(log_parts)
        if len(raw_log) > char_budget:
            raw_log = raw_log[:char_budget] + "\n... [truncated]"

        prompt = (
            f"Summarize this kernel research session log into a concise "
            f"reference that the main research model can use as context. "
            f"Focus on facts, offsets, addresses, and conclusions.\n\n"
            f"--- SESSION LOG ---\n{raw_log}\n--- END LOG ---"
        )

        try:
            summary = await self.aux_model.complete(
                prompt,
                system=_SUMMARIZE_SYSTEM,
                max_tokens=50000,
            )
            logger.debug("Aux model summary: %d chars", len(summary))
            return summary
        except Exception as e:
            logger.warning("Aux model summarization failed: %s — falling back to naive", e)
            return self._summarize_naive(messages)

    def _summarize_naive(self, messages: list[Message]) -> str:
        """Fallback: compress middle conversation into a log of actions."""
        actions: list[str] = []

        for msg in messages:
            if msg.role == Role.ASSISTANT:
                for tc in msg.tool_calls:
                    args_preview = _summarize_args(tc.arguments, max_len=80)
                    actions.append(
                        f"Called {tc.server}.{tc.tool_name}({args_preview})"
                    )
                if msg.content:
                    first_line = msg.content.split("\n")[0][:200]
                    if first_line.strip():
                        actions.append(f"Analysis: {first_line}")

            elif msg.role == Role.TOOL_RESULT:
                for tr in msg.tool_results:
                    if tr.is_error:
                        actions.append(f"Error: {tr.content[:100]}")

        actions = actions[-self.config.summary_action_limit:]
        return "\n".join(f"  {a}" for a in actions) if actions else "  (no actions)"

    def _truncate_tool_results(self, messages: list[Message]) -> list[Message]:
        """
        Truncate oversized tool results to save tokens.
        Returns a new list — originals not mutated.
        """
        max_chars = self.config.max_tool_result_chars
        result: list[Message] = []

        for msg in messages:
            if msg.role == Role.TOOL_RESULT and msg.tool_results:
                new_results = []
                for tr in msg.tool_results:
                    if len(tr.content) > max_chars:
                        truncated = (
                            tr.content[:max_chars]
                            + f"\n\n... [truncated - {len(tr.content)} chars total]"
                        )
                        new_results.append(ToolResult(
                            tool_call_id=tr.tool_call_id,
                            content=truncated,
                            is_error=tr.is_error,
                        ))
                    else:
                        new_results.append(tr)

                new_msg = Message(
                    role=msg.role,
                    tool_results=new_results,
                    provider=msg.provider,
                    model=msg.model,
                    timestamp=msg.timestamp,
                )
                result.append(new_msg)
            else:
                result.append(msg)

        return result


def _summarize_args(args: dict, max_len: int = 80) -> str:
    """Short preview of tool arguments for logging."""
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
