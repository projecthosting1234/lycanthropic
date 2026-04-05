from __future__ import annotations

import os
from pathlib import Path
import sys

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from analysis.common.debug import logger

import idapro

import ida_funcs
import ida_name
import ida_nalt
import ida_typeinf
import ida_xref
import idautils
import idc
import ida_hexrays

_ida_initialized = False


def ensure_ida() -> None:
    global _ida_initialized
    if _ida_initialized:
        return
    import idapro

    idapro.enable_console_messages(False)
    _ida_initialized = True


def open_ida_db(file_path: str) -> None:
    ensure_ida()
    import ida_auto
    import idapro

    if not os.path.isfile(file_path):
        logger.info("open_ida_db missing file=%s", file_path)
        raise FileNotFoundError(file_path)
    if idapro.open_database(file_path, True) != 0:
        raise RuntimeError(f"failed to open database for {file_path}")
    ida_auto.auto_wait()

def close_ida_db() -> None:
    import idapro
    idapro.close_database(False)


def init_hexrays() -> bool:
    try:
        import ida_hexrays
        result = ida_hexrays.init_hexrays_plugin()
        return result
    except Exception:
        return False

def name_from_address(ea: int) -> str:
    name = ida_funcs.get_func_name(ea)
    result = name or idc.get_name(ea) or f"sub_{ea:x}"
    return result


def func_start(ea: int) -> int:
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return func.start_ea


def is_import(callee_ea: int) -> bool:
    seg_name = idc.get_segm_name(callee_ea) or ""
    if seg_name in {".idata", "extern"}:
        return True
    result = is_thunk(callee_ea) and any(idc.get_segm_name(target) in {".idata", "extern"} for target in all_call_targets(callee_ea))
    return result

def is_intrinsic(callsite_ea: int) -> bool:
    func = ida_funcs.get_func(callsite_ea)
    if func is None:
        return True
    return False

def is_thunk(ea: int) -> bool:
    func = ida_funcs.get_func(ea)
    return func is not None and bool(func.flags & ida_funcs.FUNC_THUNK)

def _get_rdata_section() -> tuple[int, int] | None:
    """Get .rdata section bounds (start, end)."""
    import ida_segment
    
    # Find .rdata section by name
    seg = ida_segment.get_segm_by_name(".rdata")
    if seg:
        return (seg.start_ea, seg.end_ea)
    
    return None
    
def return_bitwidth(func_ea: int) -> int:
    """Bitwidth of the function's return type (e.g. 8 for IRQL, 32 for unsigned int)."""
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, func_ea):
        return 64
    ret_type = tif.get_rettype()
    if ret_type is None or ret_type.empty():
        return 64
    try:
        size = ret_type.get_size()
        return 64 if size <= 0 else size * 8
    except Exception:
        return 64


def param_bitwidth(func_ea: int, param_index: int) -> int:
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, func_ea):
        return 64
    func_details = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(func_details):
        return 64
    if param_index < 0 or param_index >= len(func_details):
        return 64
    arg_type = func_details[param_index].type
    size = arg_type.get_size()
    result = 64 if size <= 0 else size * 8
    return result


def input_file_name() -> str:
    result = os.path.basename(ida_nalt.get_input_file_path())
    return result


def all_call_targets(func_ea: int) -> list[int]:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return []
    targets: set[int] = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for target in idautils.CodeRefsFrom(head, False):
            callee = ida_funcs.get_func(target)
            if callee is not None:
                targets.add(callee.start_ea)
    return sorted(targets)

def get_typeinfo(ea_int: int) -> ida_typeinf.tinfo_t:
    symbol_name = name_from_address(ea_int)
    typeinfo = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(typeinfo, ea_int)
    return typeinfo

def init_hexrays() -> bool:
    """Initialize the Hex-Rays decompiler. Returns True if available."""
    try:
        result = ida_hexrays.init_hexrays_plugin()
        return result
    except Exception:
        return False

def get_pseudocode(ea_int: int) -> tuple[ida_hexrays.cfuncptr_t, tuple[int, int]]:
    """Decompile, return code with line and column number corresponding to ea"""

    cfunc = ida_hexrays.decompile(ea_int)
    citem = cfunc.body.find_closest_addr(ea_int)
    coord = cfunc.find_item_coords(citem)

    # because line number start at 1
    coord2 = (coord[0] - 1, coord[1])
    return cfunc, coord2    # type: ignore

def get_disasm_line(ea_int: int):
    return idc.generate_disasm_line(ea_int, 0)
    