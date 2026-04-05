"""
Token caching layer for the orchestrator.

Three caching strategies working together:

1. **Provider prompt caching** — Handled inside each adapter:
   - Anthropic: cache_control breakpoints on system prompt, tools, message prefix
   - OpenAI: automatic prefix caching via stable message ordering
   Both reduce input token costs by avoiding re-tokenization of static content.

2. **Tool result caching** — Local LRU cache for deterministic MCP tool calls.
   If the model asks for the same struct offset or symbol resolution twice,
   return the cached result without hitting the MCP server. Saves latency
   and avoids redundant IPC.

3. **Conversation prefix hashing** — Track which message prefix has been
   sent to each provider, so we can measure cache effectiveness and
   optimize breakpoint placement.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from orchestrator.models import ToolCall, ToolResult

logger = logging.getLogger(__name__)


# ── Tool Result Cache ──────────────────────────────────────────────────

# Tools whose results are deterministic for a given set of arguments.
# These are safe to cache — the same input always produces the same output
# (within a debugging session where the target hasn't changed state).
CACHEABLE_TOOLS: dict[str, set[str]] = {
    "windbg": {
        "resolve_symbol",
        "evaluate_expression",
        "get_struct_offset",
        "get_build_profile",
        "list_build_profiles",
    },
    "ida": {
        "get_function_info",
        "decompile",
        "get_xrefs_to",
        "get_xrefs_from",
        "find_callers",
        "get_basic_blocks",
        "get_call_graph",
        "get_block_disassembly",
        "get_cfg_summary",
        "list_strings",
        "list_imports",
        "list_exports",
        "list_segments",
        "list_names",
        "list_structs",
        "get_struct_details",
        "get_type_at",
        "search_bytes",
        "search_text",
        "search_immediate",
        "get_database_info",
    },
    "gadget": {
        "find_gadgets",
        "find_stack_pivot",
        "find_write_primitive",
        "find_call_target",
        "semantic_search",
        "get_index_status",
    },
    "sysinternals": {
        "browse_object_directory",
        "resolve_symlink",
        "get_security_descriptor",
        "get_tool_status",
    },
}


def _make_cache_key(tool_call: ToolCall) -> str:
    """Deterministic cache key for a tool call."""
    payload = {
        "server": tool_call.server,
        "tool": tool_call.tool_name,
        "args": tool_call.arguments,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def is_cacheable(tool_call: ToolCall) -> bool:
    """Check if a tool call's result can be cached."""
    server_tools = CACHEABLE_TOOLS.get(tool_call.server)
    if server_tools is None:
        return False
    return tool_call.tool_name in server_tools


@dataclass
class CacheEntry:
    result: ToolResult
    created_at: float
    hit_count: int = 0


class ToolResultCache:
    """
    LRU cache for deterministic tool call results.

    Avoids redundant MCP server round-trips when the model asks for the
    same data twice (common with struct offsets, symbol resolution, etc.).
    """

    def __init__(self, max_size: int = 512, ttl_seconds: float = 3600.0):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    def get(self, tool_call: ToolCall) -> ToolResult | None:
        """Look up cached result. Returns None on miss."""
        if not is_cacheable(tool_call):
            return None

        key = _make_cache_key(tool_call)
        entry = self._cache.get(key)

        if entry is None:
            self._misses += 1
            return None

        # TTL check
        if time.time() - entry.created_at > self._ttl:
            del self._cache[key]
            self._misses += 1
            return None

        # LRU: move to end
        self._cache.move_to_end(key)
        entry.hit_count += 1
        self._hits += 1

        # Return a copy with the correct tool_call_id
        return ToolResult(
            tool_call_id=tool_call.id,
            content=entry.result.content,
            is_error=entry.result.is_error,
        )

    def put(self, tool_call: ToolCall, result: ToolResult) -> None:
        """Store a result in the cache."""
        if not is_cacheable(tool_call):
            return
        if result.is_error:
            return  # Don't cache errors

        key = _make_cache_key(tool_call)

        # Evict oldest if at capacity
        while len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)

        self._cache[key] = CacheEntry(
            result=result,
            created_at=time.time(),
        )

    def invalidate(self, server: str | None = None) -> int:
        """
        Invalidate cached entries. If server is given, only invalidate
        entries for that server. Returns count of evicted entries.

        Call this when target state changes (e.g., breakpoint hit,
        memory write, process switch) to avoid stale data.
        """
        if server is None:
            count = len(self._cache)
            self._cache.clear()
            return count

        to_remove = [
            k for k, v in self._cache.items()
            if v.result.tool_call_id.startswith(f"tc_")  # all entries
        ]
        # Re-check by reconstructing — simpler to just tag entries
        # For now, full invalidation per server is done by clearing all
        # since keys are hashes. A production version would tag entries.
        if server in ("windbg",):
            # WinDbg state can change — invalidate all WinDbg entries
            count = len(self._cache)
            self._cache.clear()
            return count
        return 0

    def invalidate_all(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()

    @property
    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / max(total, 1),
            "ttl_seconds": self._ttl,
        }


# ── Prompt Cache Tracker ───────────────────────────────────────────────

@dataclass
class PromptCacheStats:
    """
    Tracks prompt cache effectiveness across turns.

    Aggregates cache_read_tokens and cache_creation_tokens reported
    by provider APIs to measure how much we're saving.
    """

    total_input_tokens: int = 0
    total_cache_read_tokens: int = 0
    total_cache_creation_tokens: int = 0
    turns_with_cache_hit: int = 0
    total_turns: int = 0

    def record(
        self,
        input_tokens: int,
        cache_read: int,
        cache_creation: int,
    ) -> None:
        self.total_input_tokens += input_tokens
        self.total_cache_read_tokens += cache_read
        self.total_cache_creation_tokens += cache_creation
        self.total_turns += 1
        if cache_read > 0:
            self.turns_with_cache_hit += 1

    @property
    def cache_hit_rate(self) -> float:
        """Fraction of input tokens served from cache."""
        if self.total_input_tokens == 0:
            return 0.0
        return self.total_cache_read_tokens / self.total_input_tokens

    @property
    def estimated_savings_ratio(self) -> float:
        """
        Estimated cost savings from prompt caching.

        Anthropic charges 90% less for cache reads vs fresh input.
        OpenAI charges 50% less for cached prefix tokens.
        We use a blended estimate of 75% savings on cached tokens.
        """
        if self.total_input_tokens == 0:
            return 0.0
        cached = self.total_cache_read_tokens
        return (cached * 0.75) / self.total_input_tokens

    def summary(self) -> dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "cache_read_tokens": self.total_cache_read_tokens,
            "cache_creation_tokens": self.total_cache_creation_tokens,
            "cache_hit_rate": f"{self.cache_hit_rate:.1%}",
            "estimated_savings": f"{self.estimated_savings_ratio:.1%}",
            "turns_with_cache_hit": f"{self.turns_with_cache_hit}/{self.total_turns}",
        }


# ── Unified Cache Manager ─────────────────────────────────────────────

class CacheManager:
    """
    Unified cache manager aggregating all caching strategies.

    Used by the Orchestrator to:
    1. Check tool result cache before dispatching to MCP servers
    2. Track prompt cache stats from provider responses
    3. Invalidate caches when target state changes
    """

    def __init__(
        self,
        tool_cache_size: int = 512,
        tool_cache_ttl: float = 3600.0,
    ):
        self.tool_cache = ToolResultCache(
            max_size=tool_cache_size,
            ttl_seconds=tool_cache_ttl,
        )
        self.prompt_cache = PromptCacheStats()

    def record_api_call(
        self,
        input_tokens: int,
        cache_read: int,
        cache_creation: int,
    ) -> None:
        """Record prompt cache stats from a provider API response."""
        self.prompt_cache.record(input_tokens, cache_read, cache_creation)

    def on_state_change(self, event: str = "general") -> None:
        """
        Invalidate caches when debugger state changes.

        Events:
        - "breakpoint_hit" → invalidate WinDbg live-state tools
        - "memory_write" → invalidate WinDbg memory reads
        - "process_switch" → invalidate everything
        - "general" → invalidate WinDbg caches only
        """
        if event in ("process_switch", "target_change"):
            self.tool_cache.invalidate_all()
        else:
            self.tool_cache.invalidate(server="windbg")

    def summary(self) -> dict[str, Any]:
        return {
            "tool_cache": self.tool_cache.stats,
            "prompt_cache": self.prompt_cache.summary(),
        }
