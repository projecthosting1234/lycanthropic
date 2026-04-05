"""Windows-specific symbol table construction and structural constraints

Generates structurally-guaranteed constraints from Windows kernel invariants
and the field registry -- not from pseudocode analysis.

Four categories:
  1. IOCTL method bits: constrain Extract(1, 0, ioctl_code) based on buffer methods
  2. Buffer length minimum: in_len/out_len >= max(offset + width) from field registry
  3. Buffer provenance: structural axioms based on IOCTL method (METHOD_BUFFERED etc.)
  4. Max-offset length: in_len/out_len >= max byte offset accessed per buffer
"""

from __future__ import annotations

from pathlib import Path
import re
from dataclasses import dataclass, field
from enum import Enum
import sys

from analysis.ir_schema import BVSort, Constraint, Expr, ExprOp, PtrSort, Symbol, scoped_name
from analysis.ir_to_z3.symbols import SymbolTable, SymbolTableBuilder


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Buffer-symbol to length-symbol mapping.
# userbuf_base -> out_len: for METHOD_NEITHER, Irp->UserBuffer is the
# output buffer addressed by OutputBufferLength.  The input buffer for
# METHOD_NEITHER is Type3InputBuffer (params_base), addressed by in_len.
# params_base -> in_len: METHOD_NEITHER raw parameter pointer (input side).
_BUF_TO_LEN: dict[str, str] = {
    "inbuf_base": "in_len",
    "outbuf_base": "out_len",
    "userbuf_base": "out_len",
    "mdlbuf_base": "out_len",
    "params_base": "in_len",
}


# ── Feature 4B: Max-offset length constraints ────────────────────

def _buffer_length_constraints(st: SymbolTable) -> list[Constraint]:
    """Constrain buffer lengths to cover all registered fields.

    For each buffer in the FieldRegistry, the corresponding length symbol
    must be >= max(offset + width) across all registered fields.
    """
    # Group fields by buffer_symbol -> max end offset
    by_buffer: dict[str, int] = {}
    for fa in st.fields._accesses.values():
        end = fa.offset + fa.width
        by_buffer[fa.buffer_symbol] = max(by_buffer.get(fa.buffer_symbol, 0), end)

    constraints: list[Constraint] = []
    cid = 0
    for buf_sym, min_bytes in sorted(by_buffer.items()):
        len_sym = _BUF_TO_LEN.get(buf_sym)
        if len_sym is None or len_sym not in st.symbols:
            continue

        expr = Expr(op="bvuge", args=[
            Expr(op=ExprOp.SYMBOL, symbol=len_sym),
            Expr(literal=min_bytes, bitwidth=32),
        ])
        constraints.append(Constraint(
            id=f"c_domain_buflen_{cid}",
            expr=expr,
            parent_block_ea="domain",
            kind="domain",
            confidence=1.0,
            comment=f"{len_sym} >= {min_bytes} (0x{min_bytes:x}) to cover {buf_sym} fields",
        ))
        cid += 1

    return constraints


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

class DriverModel(str, Enum):
    WDM = "WDM"
    KMDF = "KMDF"
    UNKNOWN = "Unknown"


class BufferMethod(str, Enum):
    SYSTEM_BUFFER = "system_buffer"
    USER_BUFFER = "user_buffer"
    MDL = "mdl"
    KMDF_INPUT = "kmdf_input"
    KMDF_OUTPUT = "kmdf_output"
    UNKNOWN = "unknown"


# ── Feature 4A: Buffer provenance constraints ────────────────────


# IOCTL method constants
METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3



def _buffer_provenance_constraints(st: SymbolTable) -> list[Constraint]:
    """Hard structural axioms based on IOCTL method.

    METHOD_BUFFERED (0): inbuf_base == outbuf_base (same SystemBuffer)
    METHOD_NEITHER (3):  bvult(userbuf_base, 0x7FFFFFFFFFFF) (user-space pointer)
    METHOD_DIRECT (1/2): ne(inbuf_base, mdlbuf_base) (distinct buffers)
    """
    constraints: list[Constraint] = []
    cid = 0

    for bm in st.buffer_methods:
        if bm in (BufferMethod.SYSTEM_BUFFER, BufferMethod.KMDF_INPUT):
            # METHOD_BUFFERED: input and output share the same SystemBuffer
            # Only emit if both symbols exist AND outbuf_base is NOT already an alias
            if ("inbuf_base" in st.symbols
                    and "outbuf_base" in st.symbols
                    and "outbuf_base" not in st.aliases):
                constraints.append(Constraint(
                    id=f"c_domain_provenance_{cid}",
                    expr=Expr(op="eq", args=[
                        Expr(op=ExprOp.SYMBOL, symbol="inbuf_base"),
                        Expr(op=ExprOp.SYMBOL, symbol="outbuf_base"),
                    ]),
                    parent_block_ea="domain",
                    kind="domain",
                    confidence=1.0,
                    comment="METHOD_BUFFERED: inbuf_base == outbuf_base (same SystemBuffer)",
                ))
                cid += 1

        elif bm in (BufferMethod.USER_BUFFER, BufferMethod.UNKNOWN):
            # METHOD_NEITHER: user-space pointer (below kernel boundary)
            if "userbuf_base" in st.symbols:
                constraints.append(Constraint(
                    id=f"c_domain_provenance_{cid}",
                    expr=Expr(op="bvult", args=[
                        Expr(op=ExprOp.SYMBOL, symbol="userbuf_base"),
                        Expr(literal=0x7FFFFFFFFFFF, bitwidth=64),
                    ]),
                    parent_block_ea="domain",
                    kind="domain",
                    confidence=1.0,
                    comment="METHOD_NEITHER: userbuf_base is a user-space pointer",
                ))
                cid += 1

        elif bm == BufferMethod.MDL:
            # METHOD_DIRECT: SystemBuffer and MDL buffer are distinct
            if "inbuf_base" in st.symbols and "mdlbuf_base" in st.symbols:
                constraints.append(Constraint(
                    id=f"c_domain_provenance_{cid}",
                    expr=Expr(op="ne", args=[
                        Expr(op=ExprOp.SYMBOL, symbol="inbuf_base"),
                        Expr(op=ExprOp.SYMBOL, symbol="mdlbuf_base"),
                    ]),
                    parent_block_ea="domain",
                    kind="domain",
                    confidence=1.0,
                    comment="METHOD_DIRECT: inbuf_base != mdlbuf_base (distinct buffers)",
                ))
                cid += 1

    return constraints



# -- Step 5a: Driver model detection --

def _detect_driver_model(sym_table_builder, table: SymbolTable) -> None:
    stop_kind = sym_table_builder._finding.get("stop_kind", "")

    # Priority 1: stop_kind (most reliable)
    if stop_kind in (
        "WDM_DriverEntry_MajorFunction_Assignment",
        "WDM_DriverEntry_top_of_graph",
    ):
        table.driver_model = DriverModel.WDM
    elif stop_kind in (
        "KMDF_WdfIoQueueCreate_Callback_Registration",
        "KMDF_WdfDriverCreate_EvtDriverDeviceAdd_Registration",
    ):
        table.driver_model = DriverModel.KMDF
    else:
        # Priority 2: majority vote from chain_facts
        votes: dict[str, int] = {}
        for cf in sym_table_builder._chain_facts:
            if cf is None:
                continue
            guess = cf.get("driver_model_guess", "")
            if guess:
                votes[guess] = votes.get(guess, 0) + 1
        if votes:
            winner = max(votes, key=lambda k: votes[k])
            if winner == "WDM":
                table.driver_model = DriverModel.WDM
            elif winner == "KMDF":
                table.driver_model = DriverModel.KMDF
            # "Mixed" / "Unknown" -> DriverModel.UNKNOWN

    # Buffer method detection from LLM's inference
    methods: list[BufferMethod] = []
    for cf in sym_table_builder._chain_facts:
        if cf is None:
            continue

        wdm = cf.get("wdm_indicators", {})
        if wdm.get("reads_systembuffer"):
            if BufferMethod.SYSTEM_BUFFER not in methods:
                methods.append(BufferMethod.SYSTEM_BUFFER)
        if wdm.get("reads_userbuffer"):
            if BufferMethod.USER_BUFFER not in methods:
                methods.append(BufferMethod.USER_BUFFER)
        if wdm.get("reads_mdl"):
            if BufferMethod.MDL not in methods:
                methods.append(BufferMethod.MDL)

        kmdf = cf.get("kmdf_indicators", {})
        if kmdf.get("calls_wdf_retrieve_input"):
            if BufferMethod.KMDF_INPUT not in methods:
                methods.append(BufferMethod.KMDF_INPUT)
        if kmdf.get("calls_wdf_retrieve_output"):
            if BufferMethod.KMDF_OUTPUT not in methods:
                methods.append(BufferMethod.KMDF_OUTPUT)

    # Buffer method detection from extracted IOCTL codes

    table.buffer_methods = methods

# -- Step 5b: Root symbols --

def _add_root_symbols(self, table: SymbolTable) -> None:
    is_kmdf = table.driver_model == DriverModel.KMDF

    ioctl_origin = (
        "WdfRequestGetParameters().Parameters.DeviceIoControl.IoControlCode"
        if is_kmdf
        else "IoStackLocation->Parameters.DeviceIoControl.IoControlCode"
    )
    inlen_origin = (
        "WdfRequestGetParameters().Parameters.DeviceIoControl.InputBufferLength"
        if is_kmdf
        else "IoStackLocation->Parameters.DeviceIoControl.InputBufferLength"
    )
    outlen_origin = (
        "WdfRequestGetParameters().Parameters.DeviceIoControl.OutputBufferLength"
        if is_kmdf
        else "IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength"
    )

    table.add(Symbol(
        name="ioctl_code", sort=BVSort(32), bitwidth=32,
        domain="ioctl_code", origin=ioctl_origin,
    ))
    table.add(Symbol(
        name="in_len", sort=BVSort(32), bitwidth=32,
        domain="length", origin=inlen_origin,
    ))
    table.add(Symbol(
        name="out_len", sort=BVSort(32), bitwidth=32,
        domain="length", origin=outlen_origin,
    ))

# -- Step 5c: Buffer base symbols --

_BUFFER_INFO: dict[BufferMethod, tuple[str, str, str]] = {
    # method -> (symbol_name, wdm_origin, kmdf_origin)
    BufferMethod.SYSTEM_BUFFER: (
        "inbuf_base",
        "Irp->AssociatedIrp.SystemBuffer",
        "WdfRequestRetrieveInputBuffer(Request)",
    ),
    BufferMethod.USER_BUFFER: (
        "userbuf_base",
        "Irp->UserBuffer",
        "Irp->UserBuffer",
    ),
    BufferMethod.MDL: (
        "mdlbuf_base",
        "MmGetSystemAddressForMdlSafe(Irp->MdlAddress)",
        "MmGetSystemAddressForMdlSafe(Irp->MdlAddress)",
    ),
    BufferMethod.KMDF_INPUT: (
        "inbuf_base",
        "WdfRequestRetrieveInputBuffer(Request)",
        "WdfRequestRetrieveInputBuffer(Request)",
    ),
    BufferMethod.KMDF_OUTPUT: (
        "outbuf_base",
        "WdfRequestRetrieveOutputBuffer(Request)",
        "WdfRequestRetrieveOutputBuffer(Request)",
    ),
}

def _add_buffer_symbols(sym_table_builder, table: SymbolTable) -> None:
    is_kmdf = table.driver_model == DriverModel.KMDF

    for method in table.buffer_methods:
        info = _BUFFER_INFO.get(method)
        if info is None:
            continue
        sym_name, wdm_origin, kmdf_origin = info
        origin = kmdf_origin if is_kmdf else wdm_origin

        table.add(Symbol(
            name=sym_name, sort=PtrSort(64), bitwidth=64,
            domain="pointer", origin=origin,
        ))

    # For METHOD_BUFFERED (SYSTEM_BUFFER / KMDF_INPUT), the same buffer
    # serves as both input and output.  Ensure outbuf_base exists as an
    # alias so output-side constraints and PoC rendering work correctly.
    buffered_methods = {BufferMethod.SYSTEM_BUFFER, BufferMethod.KMDF_INPUT}
    if any(m in buffered_methods for m in table.buffer_methods):
        if "inbuf_base" in table.symbols and "outbuf_base" not in table.symbols:
            table.add_alias("outbuf_base", "inbuf_base")

    # Register aliases from chain_facts
    for cf in sym_table_builder._chain_facts:
        if cf is None:
            continue

        wdm = cf.get("wdm_indicators", {})

        # SystemBuffer expression alias
        sb_expr = wdm.get("systembuffer_expr")
        if sb_expr and "inbuf_base" in table.symbols:
            table.add_alias("SystemBuffer", "inbuf_base")

        # UserBuffer expression alias
        ub_expr = wdm.get("userbuffer_expr")
        if ub_expr and "userbuf_base" in table.symbols:
            table.add_alias("UserBuffer", "userbuf_base")

        # Local taint hook aliases (var renames scoped by EA)
        for hook in cf.get("local_taint_hooks", []):
            hook_from = hook.get("from", "")
            hook_to = hook.get("to", "")
            hook_ea = hook.get("ea", "")
            if not (hook_from and hook_to and hook_ea):
                continue

            # Map known buffer expressions to canonical names
            target = None
            if "SystemBuffer" in hook_from and "inbuf_base" in table.symbols:
                target = "inbuf_base"
            elif "UserBuffer" in hook_from and "userbuf_base" in table.symbols:
                target = "userbuf_base"
            elif "MdlAddress" in hook_from and "mdlbuf_base" in table.symbols:
                target = "mdlbuf_base"

            if target:
                scoped_alias = scoped_name(hook_to, hook_ea)
                table.add_alias(scoped_alias, target)

# -- Step 5e: IOCTL code constraints --

def _add_ioctl_constraints(sym_table_builder, table: SymbolTable) -> None:
    ioctl_codes = sym_table_builder._finding.get("ioctl_codes", [])
    if not ioctl_codes:
        return

    eq_exprs: list[Expr] = []
    for code_str in ioctl_codes:
        code_val = int(code_str, 16) if isinstance(code_str, str) else int(code_str)
        eq_exprs.append(Expr(
            op="eq",
            args=[
                Expr(op=ExprOp.SYMBOL, symbol="ioctl_code"),
                Expr(literal=code_val, bitwidth=32),
            ],
        ))

    if len(eq_exprs) == 1:
        root_expr = eq_exprs[0]
    else:
        root_expr = Expr(op="or", args=eq_exprs)

    table.structural_constraints.append(Constraint(
        id="c_root_ioctl_guard",
        expr=root_expr,
        parent_block_ea="root",
        kind="ioctl_guard",
        model_tier=0,
        confidence=1.0,
        comment=f"IOCTL code in {{{', '.join(str(c) for c in ioctl_codes)}}}",
    ))

def build_windows_symbols(sym_table_builder: SymbolTableBuilder) -> None:
    """Main entry point to set up Windows-specific symbols and constraints."""
    sym_table = sym_table_builder.table
    _detect_driver_model(sym_table_builder, sym_table)
    _add_root_symbols(sym_table_builder, sym_table)
    _add_buffer_symbols(sym_table_builder, sym_table)
    _add_ioctl_constraints(sym_table_builder, sym_table)