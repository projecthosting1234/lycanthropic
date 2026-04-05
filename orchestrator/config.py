"""
Configuration loader — reads YAML config and builds orchestrator components.

Supports:
- Multiple provider configurations with env-var API keys
- Router strategy selection (random, alternating, strategic, budget)
- MCP server connection definitions
- Cache and pruning settings
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from orchestrator.adapters.base import AuxiliaryAdapter, ProviderAdapter
from orchestrator.adapters.claude import ClaudeAdapter, ClaudeAuxAdapter, ClaudeExtendedAdapter
from orchestrator.adapters.openai_adapter import OpenAIAdapter, OpenAIAuxAdapter
from orchestrator.bridge import MCPBridge, ServerConfig
from orchestrator.cache import CacheManager
from orchestrator.pruning import ConversationPruner, PrunerConfig
from orchestrator.routers.alternating import AlternatingRouter
from orchestrator.routers.base import AlloyRouter
from orchestrator.routers.budget import BudgetRouter
from orchestrator.routers.random_router import RandomRouter
from orchestrator.routers.strategic import StrategicRouter, StrategicRouterWithThinking

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorConfig:
    """Parsed and validated configuration."""

    # Provider adapters
    adapters: dict[str, ProviderAdapter] = field(default_factory=dict)

    # Extended thinking adapter (optional, for StrategicRouterWithThinking)
    thinking_adapter: ClaudeExtendedAdapter | None = None

    # Auxiliary adapter — small model for summarization, classification, etc.
    aux_adapter: AuxiliaryAdapter | None = None

    # Router
    router: AlloyRouter | None = None

    # MCP server configs
    server_configs: list[ServerConfig] = field(default_factory=list)

    # Orchestrator settings
    max_turns: int = 100
    max_consecutive_errors: int = 3

    # Cache settings
    tool_cache_size: int = 512
    tool_cache_ttl: float = 3600.0

    # Pruner settings
    max_context_tokens: int = 180_000
    recent_turns_to_keep: int = 20
    max_tool_result_chars: int = 8000

    # System prompt
    system_prompt: str = "You are a Windows kernel security research assistant."
    system_prompt_path: str | None = None


def load_config(path: str | Path) -> OrchestratorConfig:
    """Load configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    return _parse_config(raw)


def load_config_from_env() -> OrchestratorConfig:
    """
    Build configuration from environment variables.

    Minimal setup — just needs API keys. Uses sensible defaults for
    everything else.
    """
    config = OrchestratorConfig()

    # Providers from env
    claude_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if claude_key:
        model = os.environ.get("CLAUDE_MODEL", "claude-opus-4-6-20250514")
        config.adapters["claude"] = ClaudeAdapter(api_key=claude_key, model=model)

        # Also create thinking adapter
        thinking_budget = int(os.environ.get("CLAUDE_THINKING_BUDGET", "32768"))
        config.thinking_adapter = ClaudeExtendedAdapter(
            api_key=claude_key,
            model=model,
            thinking_budget=thinking_budget,
        )

        # Auxiliary adapter — small model for summarization etc.
        aux_model = os.environ.get("CLAUDE_AUX_MODEL", "claude-haiku-4-5-20251001")
        config.aux_adapter = ClaudeAuxAdapter(api_key=claude_key, model=aux_model)

    if openai_key:
        model = os.environ.get("OPENAI_MODEL", "gpt-4.1-2025-04-14")
        base_url = os.environ.get("OPENAI_BASE_URL")
        config.adapters["openai"] = OpenAIAdapter(
            api_key=openai_key,
            model=model,
            base_url=base_url,
        )

        # If no Claude aux adapter, use OpenAI mini as aux
        if config.aux_adapter is None:
            aux_model = os.environ.get("OPENAI_AUX_MODEL", "gpt-4.1-mini-2025-04-14")
            config.aux_adapter = OpenAIAuxAdapter(
                api_key=openai_key,
                model=aux_model,
                base_url=base_url,
            )

    if not config.adapters:
        raise ValueError(
            "No API keys found. Set ANTHROPIC_API_KEY and/or OPENAI_API_KEY"
        )

    # Router from env
    strategy = os.environ.get("ALLOY_STRATEGY", "strategic")
    config.router = _build_router(
        config.adapters,
        strategy,
        config.thinking_adapter,
    )

    # MCP servers — default to project servers
    config.server_configs = _default_server_configs()

    # System prompt
    prompt_path = os.environ.get("SYSTEM_PROMPT_PATH")
    if prompt_path and os.path.exists(prompt_path):
        with open(prompt_path, "r", encoding="utf-8") as f:
            config.system_prompt = f.read()

    return config


def _parse_config(raw: dict[str, Any]) -> OrchestratorConfig:
    """Parse raw YAML dict into OrchestratorConfig."""
    config = OrchestratorConfig()

    # --- Providers ---
    providers = raw.get("providers", {})

    if "claude" in providers:
        p = providers["claude"]
        api_key = _resolve_env(p.get("api_key_env", "ANTHROPIC_API_KEY"))
        if api_key:
            model = p.get("model", "claude-opus-4-6-20250514")
            config.adapters["claude"] = ClaudeAdapter(api_key=api_key, model=model)

            thinking = p.get("extended_thinking", {})
            if thinking.get("enabled", False):
                config.thinking_adapter = ClaudeExtendedAdapter(
                    api_key=api_key,
                    model=model,
                    thinking_budget=thinking.get("budget_tokens", 32768),
                )

            # Auxiliary model — small/cheap for summarization etc.
            aux = p.get("auxiliary", {})
            aux_model = aux.get("model", "claude-haiku-4-5-20251001")
            config.aux_adapter = ClaudeAuxAdapter(api_key=api_key, model=aux_model)

    if "openai" in providers:
        p = providers["openai"]
        api_key = _resolve_env(p.get("api_key_env", "OPENAI_API_KEY"))
        if api_key:
            model = p.get("model", "gpt-4.1-2025-04-14")
            config.adapters["openai"] = OpenAIAdapter(
                api_key=api_key,
                model=model,
                base_url=p.get("base_url"),
            )

            if config.aux_adapter is None:
                aux = p.get("auxiliary", {})
                aux_model = aux.get("model", "gpt-4.1-mini-2025-04-14")
                config.aux_adapter = OpenAIAuxAdapter(
                    api_key=api_key,
                    model=aux_model,
                    base_url=p.get("base_url"),
                )

    if not config.adapters:
        raise ValueError("No valid provider configurations found")

    # --- Router ---
    alloy = raw.get("alloy", {})
    strategy = alloy.get("strategy", "strategic")
    config.router = _build_router(
        config.adapters,
        strategy,
        config.thinking_adapter,
        alloy,
    )

    # --- MCP Servers ---
    servers = raw.get("mcp_servers", {})
    for name, srv in servers.items():
        env = {}
        for k, v in srv.get("env", {}).items():
            # Resolve env var references like ${VAR_NAME}
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                v = os.environ.get(v[2:-1], "")
            env[k] = str(v)

        config.server_configs.append(ServerConfig(
            name=name,
            command=srv.get("command", "python"),
            args=srv.get("args", []),
            env=env,
            transport=srv.get("transport", "stdio"),
        ))

    if not config.server_configs:
        config.server_configs = _default_server_configs()

    # --- Orchestrator settings ---
    orch = raw.get("orchestrator", {})
    config.max_turns = orch.get("max_turns", 100)
    config.max_consecutive_errors = orch.get("max_consecutive_errors", 3)
    config.max_context_tokens = orch.get("context_limit_tokens", 180_000)

    # --- Cache settings ---
    cache = raw.get("cache", {})
    config.tool_cache_size = cache.get("tool_cache_size", 512)
    config.tool_cache_ttl = cache.get("tool_cache_ttl", 3600.0)

    # --- System prompt ---
    kb = raw.get("knowledge_base", {})
    prompt_path = kb.get("system_prompt_path")
    if prompt_path and os.path.exists(prompt_path):
        with open(prompt_path, "r", encoding="utf-8") as f:
            config.system_prompt = f.read()

    return config


def _build_router(
    adapters: dict[str, ProviderAdapter],
    strategy: str,
    thinking_adapter: ClaudeExtendedAdapter | None = None,
    alloy_config: dict[str, Any] | None = None,
) -> AlloyRouter:
    """Build router from strategy name and config."""
    alloy_config = alloy_config or {}

    # Single provider fallback
    if len(adapters) == 1:
        only_key = list(adapters.keys())[0]
        logger.info("Single provider (%s) — using RandomRouter with weight 1.0", only_key)
        return RandomRouter(adapters, weights={only_key: 1.0})

    reasoning = alloy_config.get("reasoning_model", "claude")
    workhorse = alloy_config.get("workhorse_model", "openai")

    if strategy == "random":
        weights = alloy_config.get("weights", {k: 1.0 for k in adapters})
        return RandomRouter(adapters, weights=weights)

    elif strategy == "alternating":
        order = alloy_config.get("order", list(adapters.keys()))
        return AlternatingRouter(adapters, order=order)

    elif strategy == "strategic":
        if thinking_adapter:
            return StrategicRouterWithThinking(
                adapters,
                thinking_adapter=thinking_adapter,
                reasoning_model=reasoning,
                workhorse_model=workhorse,
            )
        return StrategicRouter(
            adapters,
            reasoning_model=reasoning,
            workhorse_model=workhorse,
        )

    elif strategy == "budget":
        premium_ratio = alloy_config.get("premium_ratio", 0.3)
        return BudgetRouter(
            adapters,
            premium_model=reasoning,
            economy_model=workhorse,
            premium_ratio=premium_ratio,
        )

    else:
        logger.warning("Unknown strategy '%s', falling back to strategic", strategy)
        return StrategicRouter(adapters, reasoning_model=reasoning, workhorse_model=workhorse)


def _resolve_env(var_name: str) -> str | None:
    """Get an environment variable value, return None if not set."""
    val = os.environ.get(var_name)
    if not val:
        logger.debug("Environment variable %s not set", var_name)
    return val


def _default_server_configs() -> list[ServerConfig]:
    """Default MCP server configurations for this project."""
    return [
        ServerConfig(
            name="windbg",
            command="python",
            args=["-m", "windbg_mcp"],
            env={
                "CONNECTION_STRING": os.environ.get("WINDBG_CONNECTION_STRING", ""),
            },
        ),
        ServerConfig(
            name="ida",
            command="python",
            args=["-m", "ida_mcp"],
            env={
                "IDA_MCP_BINARY": os.environ.get("IDA_MCP_BINARY", ""),
            },
        ),
        ServerConfig(
            name="gadget",
            command="python",
            args=["-m", "gadget_finder"],
        ),
        ServerConfig(
            name="sysinternals",
            command="python",
            args=["-m", "sysinternals_mcp"],
        ),
    ]
