"""Search tools: byte patterns, text search, immediate value search."""

import json
import logging

from mcp.server.fastmcp import Context

from ..server import mcp, get_ida_ctx, _parse_address

logger = logging.getLogger(__name__)


def _require_db(ida_ctx) -> str | None:
    if ida_ctx.db_info is None:
        return "Error: no database open. Call open_database first."
    return None


@mcp.tool()
async def search_bytes(
    pattern: str, start: str = "", max_results: int = 50, ctx: Context = None
) -> str:
    """Search for a byte pattern in the binary.

    Uses IDA's pattern syntax: hex bytes with optional wildcards.
    Example patterns: "48 8B C4 48 89 58", "CC CC CC CC", "E8 ?? ?? ?? ??"

    Args:
        pattern: Byte pattern to search for (IDA hex pattern syntax)
        start: Start address for search (hex string, default: beginning of binary)
        max_results: Maximum number of matches (default 50)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    start_ea = 0
    if start:
        try:
            start_ea = _parse_address(start)
        except ValueError:
            return f"Error: invalid start address '{start}'"

    async with ida_ctx.command_lock:
        try:
            results = await ida_ctx.client.search_bytes(pattern, start_ea, max_results)
        except ValueError as e:
            return f"Error: {e}"

    if not results:
        return f"(no matches for pattern '{pattern}')"
    lines = [f"Found {len(results)} match(es):"]
    for ea in results:
        lines.append(f"  {ea}")
    return "\n".join(lines)


@mcp.tool()
async def search_text(
    text: str, start: str = "", max_results: int = 50, ctx: Context = None
) -> str:
    """Search for text in disassembly lines.

    Searches through the disassembly text representation for matches.
    Useful for finding instructions with specific operands, comments, etc.

    Args:
        text: Text to search for in disassembly
        start: Start address (hex string, default: beginning of binary)
        max_results: Maximum number of matches (default 50)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    start_ea = 0
    if start:
        try:
            start_ea = _parse_address(start)
        except ValueError:
            return f"Error: invalid start address '{start}'"

    async with ida_ctx.command_lock:
        results = await ida_ctx.client.search_text(text, start_ea, max_results)

    if not results:
        return f"(no matches for '{text}')"
    lines = [f"Found {len(results)} match(es):"]
    for r in results:
        lines.append(f"  {r['ea']}  {r['line']}")
    return "\n".join(lines)


@mcp.tool()
async def search_immediate(
    value: str, start: str = "", max_results: int = 50, ctx: Context = None
) -> str:
    """Search for an immediate value used in instructions.

    Finds all instructions that use a specific numeric value as an operand.
    Useful for finding magic numbers, constants, syscall numbers, etc.

    Args:
        value: Immediate value to search for (hex string, e.g. "0xDEADBEEF")
        start: Start address (hex string, default: beginning of binary)
        max_results: Maximum number of matches (default 50)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    try:
        search_val = _parse_address(value)
    except ValueError:
        return f"Error: invalid value '{value}'"

    start_ea = 0
    if start:
        try:
            start_ea = _parse_address(start)
        except ValueError:
            return f"Error: invalid start address '{start}'"

    async with ida_ctx.command_lock:
        results = await ida_ctx.client.search_immediate(search_val, start_ea, max_results)

    if not results:
        return f"(no matches for immediate value {value})"
    lines = [f"Found {len(results)} match(es):"]
    for ea in results:
        lines.append(f"  {ea}")
    return "\n".join(lines)
