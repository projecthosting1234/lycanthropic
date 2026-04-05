"""IDA Pro MCP Server - Static binary analysis via idalib.

Exposes IDA Pro's analysis capabilities to Claude Code through the
Model Context Protocol. Uses FastMCP with stdio transport.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from mcp.server.fastmcp import FastMCP, Context

from .config import Config
from .ida_client import AsyncIDAClient

logger = logging.getLogger(__name__)


@dataclass
class IDAContext:
    """Shared state for the IDA analysis session."""
    client: AsyncIDAClient
    config: Config
    command_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    db_info: dict | None = None
    _bg_open_task: asyncio.Task | None = None


def get_ida_ctx(ctx: Context) -> IDAContext:
    """Extract IDAContext from MCP lifespan state."""
    return ctx.request_context.lifespan_context


def _parse_address(addr_str: str) -> int:
    """Parse a hex address string to int."""
    addr_str = addr_str.strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        return int(addr_str, 16)
    try:
        return int(addr_str, 16)
    except ValueError:
        return int(addr_str)


@asynccontextmanager
async def ida_lifespan(server: FastMCP):
    """Manage IDA lifecycle: initialize on startup, clean up on shutdown.

    The lifespan completes quickly so the MCP server can respond to Claude Code's
    ``initialize`` handshake without timing out.  If a default binary is configured,
    ``open_database`` runs as a background asyncio task.  Tools that need ``db_info``
    already check ``_require_db()`` and return a clear error while analysis is running.
    """
    config = Config.from_env()
    client = AsyncIDAClient(config)

    try:
        version = await client.initialize()
        logger.info("idalib initialized, version %s", version)

        ida_ctx = IDAContext(client=client, config=config, db_info=None)

        if config.default_binary:
            async def _bg_open():
                try:
                    logger.info("Background: opening database %s", config.default_binary)
                    async with ida_ctx.command_lock:
                        db_info = await client.open_database(
                            config.default_binary, config.auto_analysis
                        )
                    ida_ctx.db_info = db_info
                    logger.info("Background: database opened: %s (%d functions)",
                                db_info.get("file_name", "?"),
                                db_info.get("function_count", 0))
                except Exception as e:
                    logger.warning("Background DB open failed: %s", e)

            ida_ctx._bg_open_task = asyncio.create_task(_bg_open())

        yield ida_ctx  # yields immediately

    finally:
        # Cancel background task if still running
        if ida_ctx._bg_open_task and not ida_ctx._bg_open_task.done():
            ida_ctx._bg_open_task.cancel()
            try:
                await ida_ctx._bg_open_task
            except (asyncio.CancelledError, Exception):
                pass
        await client.close()
        logger.info("idalib shut down")


# Create the MCP server
mcp = FastMCP(
    "IDA Pro Analyzer",
    lifespan=ida_lifespan,
)

# Import tools and resources to register them with the server
from .tools import core as _core_tools  # noqa: E402, F401
from .tools import xrefs as _xref_tools  # noqa: E402, F401
from .tools import graph as _graph_tools  # noqa: E402, F401
from .tools import enumeration as _enum_tools  # noqa: E402, F401
from .tools import types as _type_tools  # noqa: E402, F401
from .tools import modify as _modify_tools  # noqa: E402, F401
from .tools import search as _search_tools  # noqa: E402, F401
from . import resources as _resources  # noqa: E402, F401


def main():
    """Entry point for the IDA Pro MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
