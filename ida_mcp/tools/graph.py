"""CFG and graph tools: basic blocks, call graph, block disassembly, CFG summary."""

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
async def get_basic_blocks(address: str, ctx: Context = None) -> str:
    """Get the complete control flow graph (CFG) of a function as basic blocks.

    Returns all basic blocks with their disassembly, successor/predecessor
    relationships, and edges. This is the primary tool for understanding
    function control flow.

    Args:
        address: Function address or any address within the function (hex string)
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
        try:
            result = await ida_ctx.client.get_basic_blocks(ea)
            return json.dumps(result, indent=2)
        except ValueError as e:
            return f"Error: {e}"


@mcp.tool()
async def get_call_graph(
    address: str, depth: int = 2, direction: str = "both", ctx: Context = None
) -> str:
    """Get the call graph centered on a function.

    Performs BFS traversal of call relationships to build a graph of
    callers and/or callees up to the specified depth.

    Args:
        address: Function address (hex string)
        depth: How many levels deep to traverse (default 2)
        direction: "both", "callers", or "callees"
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    try:
        ea = _parse_address(address)
    except ValueError:
        return f"Error: invalid address '{address}'"

    if direction not in ("both", "callers", "callees"):
        return f"Error: direction must be 'both', 'callers', or 'callees'"

    async with ida_ctx.command_lock:
        try:
            result = await ida_ctx.client.get_call_graph(ea, depth, direction)
            return json.dumps(result, indent=2)
        except ValueError as e:
            return f"Error: {e}"


@mcp.tool()
async def get_block_disasm(address: str, block_id: int, ctx: Context = None) -> str:
    """Get detailed disassembly of a specific basic block in a function.

    Use get_basic_blocks first to see the CFG and block IDs, then use this
    to get full byte-level disassembly of a specific block.

    Args:
        address: Function address (hex string)
        block_id: Basic block ID from get_basic_blocks output
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
        try:
            result = await ida_ctx.client.get_block_disasm(ea, block_id)
        except ValueError as e:
            return f"Error: {e}"

    lines = [f"Block {result['block_id']} ({result['start_ea']} - {result['end_ea']}):"]
    for insn in result["instructions"]:
        lines.append(f"  {insn['ea']}  {insn['bytes']:<24s}  {insn['disasm']}")
    return "\n".join(lines)


@mcp.tool()
async def get_function_cfg_summary(address: str, ctx: Context = None) -> str:
    """Get a summary of a function's control flow graph complexity.

    Returns block count, edge count, cyclomatic complexity, loop detection,
    and entry/exit blocks. Useful for quickly assessing function complexity.

    Args:
        address: Function address (hex string)
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
        try:
            result = await ida_ctx.client.get_function_cfg_summary(ea)
            return json.dumps(result, indent=2)
        except ValueError as e:
            return f"Error: {e}"
