"""
Interactive entry point for the kernel research orchestrator.

Supports two modes:
1. Interactive REPL — type queries, get responses, view stats
2. Single-shot — pass a query via --query flag

Commands in interactive mode:
  stats    — show routing breakdown, cache stats, token usage
  cache    — show cache details (tool + prompt)
  pin <f>  — pin a fact that survives pruning
  reset    — reset conversation for a new task
  quit     — exit
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from orchestrator.bridge import MCPBridge
from orchestrator.cache import CacheManager
from orchestrator.config import OrchestratorConfig, load_config, load_config_from_env
from orchestrator.orchestrator import Orchestrator
from orchestrator.pruning import ConversationPruner, PrunerConfig


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)


def _on_turn(turn: int, provider: str, model: str) -> None:
    print(f"\n  [Turn {turn}] {provider}/{model}")


def _on_tool_call(server: str, tool: str, args: dict) -> None:
    args_preview = ", ".join(
        f"{k}={str(v)[:40]}" for k, v in list(args.items())[:3]
    )
    print(f"    -> {server}.{tool}({args_preview})")


def _on_tool_result(call_id: str, preview: str, is_error: bool) -> None:
    tag = "ERR" if is_error else "OK"
    print(f"    <- [{tag}] {preview[:120]}")


async def run_interactive(config: OrchestratorConfig) -> None:
    """Run the interactive REPL loop."""
    # Build components
    cache = CacheManager(
        tool_cache_size=config.tool_cache_size,
        tool_cache_ttl=config.tool_cache_ttl,
    )
    bridge = MCPBridge(cache=cache)

    print("Connecting to MCP servers...")
    await bridge.connect(config.server_configs)

    aux_tag = f"{config.aux_adapter}" if config.aux_adapter else "none"
    pruner = ConversationPruner(
        config=PrunerConfig(
            max_context_tokens=config.max_context_tokens,
            recent_turns_to_keep=config.recent_turns_to_keep,
            max_tool_result_chars=config.max_tool_result_chars,
        ),
        aux_model=config.aux_adapter,
    )

    agent = Orchestrator(
        router=config.router,
        bridge=bridge,
        system_prompt=config.system_prompt,
        cache=cache,
        pruner=pruner,
        max_turns=config.max_turns,
        max_consecutive_errors=config.max_consecutive_errors,
        on_turn=_on_turn,
        on_tool_call=_on_tool_call,
        on_tool_result=_on_tool_result,
    )

    providers = list(config.adapters.keys())
    print(
        f"\nKernel Research Agent ready.\n"
        f"  {len(bridge.tools)} tools across {len(bridge.servers)} MCP servers\n"
        f"  Alloy (task execution): {providers}\n"
        f"  Auxiliary (summarization): {aux_tag}\n"
        f"  Router: {config.router.__class__.__name__}\n"
        f"\nCommands: stats, cache, pin <fact>, reset, quit\n"
    )

    try:
        while True:
            try:
                user_input = input("\n> ").strip()
            except EOFError:
                break

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("quit", "exit", "q"):
                break

            elif cmd == "stats":
                _print_stats(agent.get_stats())
                continue

            elif cmd == "cache":
                _print_cache(cache.summary())
                continue

            elif cmd.startswith("pin "):
                fact = user_input[4:].strip()
                if fact:
                    agent.pin_fact(fact)
                    print(f"  Pinned: {fact}")
                continue

            elif cmd == "reset":
                agent.reset()
                print("  Conversation reset.")
                continue

            # Normal query
            response = await agent.run(user_input)
            print(f"\n{response}")

    finally:
        print("\nDisconnecting...")
        await bridge.disconnect()


async def run_single(config: OrchestratorConfig, query: str) -> None:
    """Run a single query and exit."""
    cache = CacheManager(
        tool_cache_size=config.tool_cache_size,
        tool_cache_ttl=config.tool_cache_ttl,
    )
    bridge = MCPBridge(cache=cache)
    await bridge.connect(config.server_configs)

    pruner = ConversationPruner(
        config=PrunerConfig(max_context_tokens=config.max_context_tokens),
        aux_model=config.aux_adapter,
    )

    agent = Orchestrator(
        router=config.router,
        bridge=bridge,
        system_prompt=config.system_prompt,
        cache=cache,
        pruner=pruner,
        max_turns=config.max_turns,
        on_turn=_on_turn,
        on_tool_call=_on_tool_call,
        on_tool_result=_on_tool_result,
    )

    try:
        response = await agent.run(query)
        print(f"\n{response}")
        print("\n--- Stats ---")
        _print_stats(agent.get_stats())
    finally:
        await bridge.disconnect()


def _print_stats(stats: dict) -> None:
    print(f"  Turns: {stats['total_turns']}")
    print(f"  Tool calls: {stats['tool_calls']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Tokens in/out: {stats['tokens_in']:,} / {stats['tokens_out']:,}")
    print(f"  Alloy composition: {stats['alloy_composition']}")
    if "cache" in stats:
        pc = stats["cache"].get("prompt_cache", {})
        tc = stats["cache"].get("tool_cache", {})
        print(f"  Prompt cache hit rate: {pc.get('cache_hit_rate', 'N/A')}")
        print(f"  Prompt cache savings: {pc.get('estimated_savings', 'N/A')}")
        print(f"  Tool cache: {tc.get('hits', 0)} hits / {tc.get('misses', 0)} misses "
              f"({tc.get('size', 0)} entries)")


def _print_cache(summary: dict) -> None:
    print("  --- Prompt Cache ---")
    for k, v in summary.get("prompt_cache", {}).items():
        print(f"    {k}: {v}")
    print("  --- Tool Result Cache ---")
    for k, v in summary.get("tool_cache", {}).items():
        print(f"    {k}: {v}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kernel Research Agent — LLM Orchestrator with Alloying",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to YAML config file",
    )
    parser.add_argument(
        "-q", "--query",
        help="Single query to run (non-interactive mode)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    _setup_logging(args.verbose)

    # Load config
    if args.config:
        config = load_config(args.config)
    else:
        config = load_config_from_env()

    # Run
    if args.query:
        asyncio.run(run_single(config, args.query))
    else:
        asyncio.run(run_interactive(config))


if __name__ == "__main__":
    main()
