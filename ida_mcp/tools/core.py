"""Core analysis tools: open/close database, function info, disassembly, decompilation.

All address parameters are hex strings to avoid JSON 64-bit precision loss.
"""

import json
import logging

from mcp.server.fastmcp import Context

from ..server import mcp, get_ida_ctx, _parse_address

logger = logging.getLogger(__name__)


def _require_db(ida_ctx) -> str | None:
    """Return error string if no database is open, else None."""
    if ida_ctx.db_info is None:
        return "Error: no database open. Call open_database first."
    return None


@mcp.tool()
async def open_database(file_path: str, auto_analysis: bool = True, ctx: Context = None) -> str:
    """Open a binary file for analysis in IDA.

    Runs IDA's auto-analysis on the file. For large binaries (e.g., ntoskrnl.exe)
    this may take several minutes. Once open, all other tools become available.

    If the file doesn't exist locally, it will be automatically copied from the
    target VM (Hyper-V) to the local vm_binaries cache.

    Args:
        file_path: Path to the binary file (.exe, .dll, .sys, .i64, etc.)
                   Can also be just a filename (e.g. "clfs.sys") — will be
                   fetched from the VM automatically.
        auto_analysis: Wait for IDA auto-analysis to complete (default True)
    """
    ida_ctx = get_ida_ctx(ctx)

    if ida_ctx.db_info is not None:
        return "Error: a database is already open. Call close_database first."

    # Auto-resolve: copy from VM if file not found locally
    import os
    if not os.path.exists(file_path):
        try:
            from vm_copy import ensure_vm_binary
            file_path = ensure_vm_binary(file_path)
            logger.info("Resolved file via VM copy: %s", file_path)
        except FileNotFoundError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error copying from VM: {e}"

    async with ida_ctx.command_lock:
        try:
            db_info = await ida_ctx.client.open_database(file_path, auto_analysis)
            ida_ctx.db_info = db_info
            return json.dumps(db_info, indent=2)
        except Exception as e:
            return f"Error opening database: {e}"


@mcp.tool()
async def close_database(save: bool = True, ctx: Context = None) -> str:
    """Close the current IDA database.

    Args:
        save: Save changes to the .i64 database file (default True)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        try:
            await ida_ctx.client.close_database(save)
            ida_ctx.db_info = None
            return f"Database closed (save={'yes' if save else 'no'})"
        except Exception as e:
            return f"Error closing database: {e}"


@mcp.tool()
async def get_function_info(address: str, ctx: Context = None) -> str:
    """Get detailed information about a function at the given address.

    Args:
        address: Function address or any address within the function (hex string, e.g. "0x140001000")
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
            info = await ida_ctx.client.get_function_info(ea)
            return json.dumps(info, indent=2)
        except ValueError as e:
            return f"Error: {e}"


@mcp.tool()
async def list_functions(name_filter: str = "", limit: int = 500, ctx: Context = None) -> str:
    """List functions in the database, optionally filtered by name.

    Args:
        name_filter: Case-insensitive substring filter for function names (e.g. "Create", "Nt")
        limit: Maximum number of results to return (default 500)
    """
    ida_ctx = get_ida_ctx(ctx)
    err = _require_db(ida_ctx)
    if err:
        return err

    async with ida_ctx.command_lock:
        result = await ida_ctx.client.list_functions(name_filter, limit)

    lines = []
    for f in result["functions"]:
        lines.append(f"{f['start_ea']}  {f['name']}  (size: {f['size']})")
    if result["truncated"]:
        lines.append(f"\n(showing {limit} of {result['total']})")
    return "\n".join(lines) if lines else "(no functions found)"


@mcp.tool()
async def disassemble(address: str, count: int = 30, ctx: Context = None) -> str:
    """Disassemble instructions at the given address.

    Args:
        address: Start address for disassembly (hex string, e.g. "0x140001000")
        count: Number of instructions to disassemble (default 30)
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
        instructions = await ida_ctx.client.disassemble(ea, count)

    lines = []
    for insn in instructions:
        lines.append(f"{insn['ea']}  {insn['bytes']:<24s}  {insn['disasm']}")
    return "\n".join(lines) if lines else "(no instructions)"


@mcp.tool()
async def decompile(address: str, ctx: Context = None) -> str:
    """Decompile a function to C pseudocode using Hex-Rays.

    Requires the Hex-Rays decompiler. If not available, use disassemble instead.

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
            pseudocode = await ida_ctx.client.decompile(ea)
            return pseudocode
        except RuntimeError as e:
            return f"Error: {e}"
