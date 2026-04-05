"""Type information tools: list structs, struct details, type at address."""

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
async def list_structs(name_filter: str = "", limit: int = 500, ctx: Context = None) -> str:
    """List structures/types defined in the database.

    Args:
        name_filter: Case-insensitive substring filter for struct names
        limit: Maximum number of results (default 500)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_structs(name_filter, limit)

    lines = []
    for s in result["structs"]:
        lines.append(f"{s['name']:<48s}  size={s['size']}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no structures found)"


@mcp.tool()
async def get_struct_details(struct_name: str, ctx: Context = None) -> str:
    """Get detailed layout of a structure including all member offsets and types.

    Args:
        struct_name: Exact name of the structure (e.g. "_EPROCESS", "UNICODE_STRING")
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        try:
            result = await ida_ctx.client.get_struct_details(struct_name)
            return json.dumps(result, indent=2)
        except ValueError as e:
            return f"Error: {e}"


@mcp.tool()
async def get_type_at(address: str, ctx: Context = None) -> str:
    """Get the type information applied at a specific address.

    Args:
        address: Address to query (hex string)
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
        result = await ida_ctx.client.get_type_at(ea)

    return result if result else "(no type information at this address)"
