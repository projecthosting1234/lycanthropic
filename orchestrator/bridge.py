"""
MCP Tool Bridge — connects the orchestrator to MCP servers.

Collects tool schemas from all servers, dispatches tool calls, and
integrates with the tool result cache to avoid redundant IPC.

WinDbg calls are serialized (DbgEng is apartment-threaded); all other
servers can receive parallel calls.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from orchestrator.cache import CacheManager, is_cacheable
from orchestrator.models import ToolCall, ToolResult, ToolSchema

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Configuration for a single MCP server."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"


class MCPServerConnection:
    """Wraps a single MCP client session."""

    def __init__(self, name: str):
        self.name = name
        self.session: ClientSession | None = None
        self._read: Any = None
        self._write: Any = None
        self._cm: Any = None  # context manager for stdio_client

    async def connect(self, config: ServerConfig) -> list[ToolSchema]:
        """Connect to the MCP server and return its tool schemas."""
        env = {**os.environ, **config.env}
        params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=env,
        )

        self._cm = stdio_client(params)
        self._read, self._write = await self._cm.__aenter__()
        self.session = ClientSession(self._read, self._write)
        await self.session.__aenter__()
        await self.session.initialize()

        # Collect tool schemas
        tools_response = await self.session.list_tools()
        schemas: list[ToolSchema] = []
        for t in tools_response.tools:
            schemas.append(ToolSchema(
                server=config.name,
                name=t.name,
                description=t.description or "",
                parameters=t.inputSchema if t.inputSchema else {},
            ))

        logger.info(
            "Connected to %s: %d tools available",
            config.name,
            len(schemas),
        )
        return schemas

    async def call_tool(self, tool_name: str, arguments: dict) -> tuple[str, bool]:
        """Call a tool and return (content, is_error)."""
        if self.session is None:
            raise RuntimeError(f"Server {self.name} not connected")

        result = await self.session.call_tool(tool_name, arguments)

        # Extract text content from result
        content_parts: list[str] = []
        for block in result.content:
            if hasattr(block, "text"):
                content_parts.append(block.text)
            else:
                content_parts.append(str(block))

        content = "\n".join(content_parts)
        is_error = bool(result.isError) if hasattr(result, "isError") else False
        return content, is_error

    async def disconnect(self) -> None:
        """Clean up the connection."""
        if self.session:
            try:
                await self.session.__aexit__(None, None, None)
            except Exception:
                pass
        if self._cm:
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass


class MCPBridge:
    """
    Connects to all MCP servers, collects tool schemas,
    dispatches tool calls (with caching), returns results.

    WinDbg calls are serialized. All other servers run in parallel.
    """

    def __init__(self, cache: CacheManager | None = None):
        self.servers: dict[str, MCPServerConnection] = {}
        self.tools: list[ToolSchema] = []
        self.cache = cache or CacheManager()
        self._windbg_lock = asyncio.Lock()

    async def connect(self, server_configs: list[ServerConfig]) -> None:
        """Connect to all MCP servers and collect tool schemas."""
        for cfg in server_configs:
            conn = MCPServerConnection(cfg.name)
            try:
                schemas = await conn.connect(cfg)
                self.servers[cfg.name] = conn
                self.tools.extend(schemas)
            except Exception as e:
                logger.error("Failed to connect to %s: %s", cfg.name, e)
                # Continue with remaining servers

        logger.info(
            "MCPBridge ready: %d servers, %d tools",
            len(self.servers),
            len(self.tools),
        )

    async def execute_tool(self, tool_call: ToolCall) -> ToolResult:
        """
        Execute a single tool call. Checks cache first for deterministic tools.
        """
        # Check cache
        cached = self.cache.tool_cache.get(tool_call)
        if cached is not None:
            logger.debug(
                "Tool cache hit: %s.%s",
                tool_call.server,
                tool_call.tool_name,
            )
            return cached

        # Dispatch to server
        server = self.servers.get(tool_call.server)
        if not server:
            return ToolResult(
                tool_call_id=tool_call.id,
                content=f"Unknown MCP server: {tool_call.server}",
                is_error=True,
            )

        try:
            content, is_error = await server.call_tool(
                tool_call.tool_name,
                tool_call.arguments,
            )
            result = ToolResult(
                tool_call_id=tool_call.id,
                content=content,
                is_error=is_error,
            )

            # Cache if deterministic
            if not is_error:
                self.cache.tool_cache.put(tool_call, result)

            return result

        except Exception as e:
            logger.error(
                "Tool execution error: %s.%s: %s",
                tool_call.server,
                tool_call.tool_name,
                e,
            )
            return ToolResult(
                tool_call_id=tool_call.id,
                content=f"Tool execution error: {e}",
                is_error=True,
            )

    async def execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
    ) -> list[ToolResult]:
        """
        Execute multiple tool calls. Parallel where safe, serial for WinDbg.

        WinDbg is apartment-threaded (single COM thread), so its calls
        must be serialized. Other servers (IDA, Gadget, Sysinternals) can
        run concurrently.
        """
        windbg_calls = [tc for tc in tool_calls if tc.server == "windbg"]
        other_calls = [tc for tc in tool_calls if tc.server != "windbg"]

        results: dict[str, ToolResult] = {}

        # Run non-WinDbg calls in parallel
        if other_calls:
            parallel_results = await asyncio.gather(
                *[self.execute_tool(tc) for tc in other_calls],
                return_exceptions=True,
            )
            for tc, result in zip(other_calls, parallel_results):
                if isinstance(result, Exception):
                    results[tc.id] = ToolResult(
                        tool_call_id=tc.id,
                        content=f"Tool execution error: {result}",
                        is_error=True,
                    )
                else:
                    results[tc.id] = result

        # Run WinDbg calls serially under lock
        async with self._windbg_lock:
            for tc in windbg_calls:
                result = await self.execute_tool(tc)
                results[tc.id] = result

        # Return in original call order
        return [results[tc.id] for tc in tool_calls]

    async def disconnect(self) -> None:
        """Disconnect from all servers."""
        for name, conn in self.servers.items():
            try:
                await conn.disconnect()
            except Exception as e:
                logger.error("Error disconnecting %s: %s", name, e)
        self.servers.clear()
        self.tools.clear()
