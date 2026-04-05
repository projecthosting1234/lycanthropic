"""Modification tools: rename, set comments, set types."""

import logging

from mcp.server.fastmcp import Context

from ..server import mcp, get_ida_ctx, _parse_address

logger = logging.getLogger(__name__)


def _require_db(ida_ctx) -> str | None:
    if ida_ctx.db_info is None:
        return "Error: no database open. Call open_database first."
    return None


@mcp.tool()
async def rename(address: str, new_name: str, ctx: Context = None) -> str:
    """Rename a function, variable, or label at the given address.

    Args:
        address: Address of the item to rename (hex string)
        new_name: New name to apply (must be a valid C identifier)
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
        success = await ida_ctx.client.rename(ea, new_name)

    if success:
        return f"Renamed 0x{ea:x} to '{new_name}'"
    else:
        return f"Error: failed to rename 0x{ea:x} to '{new_name}' (name may be invalid or in use)"


@mcp.tool()
async def set_comment(address: str, comment: str, repeatable: bool = False, ctx: Context = None) -> str:
    """Set a comment at a specific address (instruction or data).

    Args:
        address: Address to comment (hex string)
        comment: Comment text
        repeatable: If True, comment appears at all xrefs to this address (default False)
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
        success = await ida_ctx.client.set_comment(ea, comment, repeatable)

    kind = "repeatable " if repeatable else ""
    if success:
        return f"Set {kind}comment at 0x{ea:x}"
    else:
        return f"Error: failed to set comment at 0x{ea:x}"


@mcp.tool()
async def set_function_comment(
    address: str, comment: str, repeatable: bool = False, ctx: Context = None
) -> str:
    """Set a comment on a function (shown in function header).

    Args:
        address: Function address (hex string)
        comment: Comment text
        repeatable: If True, comment appears at all call sites (default False)
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
            success = await ida_ctx.client.set_function_comment(ea, comment, repeatable)
        except ValueError as e:
            return f"Error: {e}"

    kind = "repeatable " if repeatable else ""
    if success:
        return f"Set {kind}function comment at 0x{ea:x}"
    else:
        return f"Error: failed to set function comment at 0x{ea:x}"


@mcp.tool()
async def set_type(address: str, type_string: str, ctx: Context = None) -> str:
    """Apply a C type declaration at the given address.

    Can be used to set function prototypes, variable types, etc.

    Args:
        address: Address to apply type at (hex string)
        type_string: C type string (e.g. "int __fastcall(HANDLE, PVOID)")
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
        success = await ida_ctx.client.set_type(ea, type_string)

    if success:
        return f"Applied type at 0x{ea:x}: {type_string}"
    else:
        return f"Error: failed to apply type at 0x{ea:x} (check syntax)"
