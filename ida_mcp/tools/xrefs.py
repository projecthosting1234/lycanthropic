"""Cross-reference tools: xrefs_to, xrefs_from, find_callers."""

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
async def xrefs_to(address: str, limit: int = 200, ctx: Context = None) -> str:
    """Get all cross-references TO the given address.

    Shows what code/data references this address. Useful for finding who calls
    a function, who reads/writes a global, etc.

    Args:
        address: Target address (hex string, e.g. "0x140001000")
        limit: Maximum number of results (default 200)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    try:
        ea = _parse_address(address)
    except ValueError:
        return f"Error: invalid address '{address}'"

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.xrefs_to(ea, limit)

    lines = []
    for x in result["xrefs"]:
        name = f"  ({x['from_name']})" if x['from_name'] else ""
        lines.append(f"{x['from_ea']}  type={x['type']}{name}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no xrefs to this address)"


@mcp.tool()
async def xrefs_from(address: str, limit: int = 200, ctx: Context = None) -> str:
    """Get all cross-references FROM the given address.

    Shows what this address references — calls, data reads, jumps, etc.

    Args:
        address: Source address (hex string, e.g. "0x140001000")
        limit: Maximum number of results (default 200)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    try:
        ea = _parse_address(address)
    except ValueError:
        return f"Error: invalid address '{address}'"

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.xrefs_from(ea, limit)

    lines = []
    for x in result["xrefs"]:
        name = f"  ({x['to_name']})" if x['to_name'] else ""
        lines.append(f"{x['to_ea']}  type={x['type']}{name}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no xrefs from this address)"


@mcp.tool()
async def find_callers(address: str, limit: int = 200, ctx: Context = None) -> str:
    """Find all code locations that call the function at the given address.

    A specialized version of xrefs_to that only returns code cross-references
    (call instructions). Each result includes the calling function name.

    Args:
        address: Function address (hex string, e.g. "0x140001000")
        limit: Maximum number of results (default 200)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    try:
        ea = _parse_address(address)
    except ValueError:
        return f"Error: invalid address '{address}'"

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.find_callers(ea, limit)

    lines = []
    for c in result["callers"]:
        name = f"  ({c['caller_name']})" if c['caller_name'] else ""
        lines.append(f"{c['caller_ea']}{name}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no callers found)"
