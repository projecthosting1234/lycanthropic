"""Enumeration tools: strings, imports, exports, segments, names."""

import json
import logging

from mcp.server.fastmcp import Context

from ..server import mcp, get_ida_ctx

logger = logging.getLogger(__name__)


def _require_db(ida_ctx) -> str | None:
    if ida_ctx.db_info is None:
        return "Error: no database open. Call open_database first."
    return None


@mcp.tool()
async def list_strings(
    min_length: int = 5, filter: str = "", limit: int = 500, ctx: Context = None
) -> str:
    """List strings found in the binary.

    Args:
        min_length: Minimum string length to include (default 5)
        filter: Case-insensitive substring filter (e.g. "error", "password")
        limit: Maximum number of results (default 500)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_strings(min_length, filter, limit)

    lines = []
    for s in result["strings"]:
        lines.append(f"{s['ea']}  [{s['length']:>4d}]  {s['value']}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no strings found)"


@mcp.tool()
async def list_imports(module_filter: str = "", limit: int = 1000, ctx: Context = None) -> str:
    """List imported functions grouped by module.

    Args:
        module_filter: Case-insensitive filter for module name (e.g. "ntdll", "kernel32")
        limit: Maximum total imports to return (default 1000)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_imports(module_filter, limit)

    lines = []
    for mod in result["modules"]:
        lines.append(f"\n[{mod['module']}]")
        for imp in mod["imports"]:
            name = imp["name"] or f"ordinal #{imp['ordinal']}"
            lines.append(f"  {imp['ea']}  {name}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total_imports']})")
    return "\n".join(lines).strip() if lines else "(no imports found)"


@mcp.tool()
async def list_exports(name_filter: str = "", limit: int = 1000, ctx: Context = None) -> str:
    """List exported functions and symbols.

    Args:
        name_filter: Case-insensitive substring filter for export names
        limit: Maximum number of results (default 1000)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_exports(name_filter, limit)

    lines = []
    for exp in result["exports"]:
        lines.append(f"{exp['ea']}  {exp['name']}  (ordinal: {exp['ordinal']})")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no exports found)"


@mcp.tool()
async def list_segments(ctx: Context = None) -> str:
    """List all segments (sections) in the binary.

    Returns segment name, address range, size, class, permissions, and bitness.
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        segments = await ida_ctx.client.list_segments()

    lines = []
    for seg in segments:
        lines.append(
            f"{seg['name']:<16s}  {seg['start_ea']}-{seg['end_ea']}  "
            f"size={seg['size']:<10d}  {seg['perms']}  "
            f"class={seg['class']}  {seg['bitness']}bit"
        )
    return "\n".join(lines) if lines else "(no segments)"


@mcp.tool()
async def list_names(name_filter: str = "", limit: int = 500, ctx: Context = None) -> str:
    """List named locations (symbols) in the database.

    Args:
        name_filter: Case-insensitive substring filter
        limit: Maximum number of results (default 500)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_names(name_filter, limit)

    lines = []
    for n in result["names"]:
        lines.append(f"{n['ea']}  {n['name']}")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no names found)"
