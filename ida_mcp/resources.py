"""MCP Resources for IDA Pro database state."""

import json
import logging

from mcp.server.fastmcp import Context

from .server import mcp, get_ida_ctx

logger = logging.getLogger(__name__)


@mcp.resource("ida://database/info")
async def database_info(ctx: Context) -> str:
    """Current database metadata: path, architecture, bitness, function count, Hex-Rays availability."""
    ida_ctx = get_ida_ctx(ctx)

    if ida_ctx.db_info is None:
        return json.dumps({"status": "no database open"})

    # Refresh info from the database
    try:
        async with ida_ctx.command_lock:
            info = await ida_ctx.client.get_db_info()
        ida_ctx.db_info = info
        return json.dumps(info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource("ida://database/segments")
async def database_segments(ctx: Context) -> str:
    """List of segments in the current database."""
    ida_ctx = get_ida_ctx(ctx)

    if ida_ctx.db_info is None:
        return json.dumps({"status": "no database open"})

    try:
        async with ida_ctx.command_lock:
            segments = await ida_ctx.client.list_segments()
        return json.dumps(segments, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource("ida://analysis/status")
async def analysis_status(ctx: Context) -> str:
    """Current analysis status: database open state, idalib version, Hex-Rays availability."""
    ida_ctx = get_ida_ctx(ctx)

    result = {
        "idalib_version": ida_ctx.client.version,
        "database_open": ida_ctx.client.is_db_open,
        "has_hexrays": ida_ctx.client.has_hexrays,
    }

    if ida_ctx.db_info:
        result["file_name"] = ida_ctx.db_info.get("file_name", "")
        result["function_count"] = ida_ctx.db_info.get("function_count", 0)

    return json.dumps(result, indent=2)
