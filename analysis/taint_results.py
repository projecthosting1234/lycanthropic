"""Taint policy for WDM LPE analysis.

Defines which entities should be considered tainted (attacker-controlled) and
propagation rules for binary operations, memory reads, and sink checks.
Validates taint chains against the policy to detect overtaint/undertaint.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .ir import scoped_name
from analysis.ir_to_z3.symbols import SymbolTable


# ------------------------------------------------------------------
# TaintDiagnostic
# ------------------------------------------------------------------

@dataclass
class TaintDiagnostic:
    symbol_name: str
    source_ea: str
    diagnosis: str        # "overtaint" | "undertaint" | "ok"
    reason: str
    chain_confidence: float


# ------------------------------------------------------------------
# TaintPolicy ABC
# ------------------------------------------------------------------

class TaintPolicy(ABC):
    @abstractmethod
    def p_input(self, source: str, context: dict | None = None) -> bool: ...

    @abstractmethod
    def p_const(self) -> bool: ...

    @abstractmethod
    def p_binop(self, t1: bool, t2: bool) -> bool: ...

    @abstractmethod
    def p_mem_read(self, t_addr: bool, t_value: bool) -> bool: ...

    @abstractmethod
    def p_sink_check(self, sink_name: str, tainted_args: list[bool]) -> bool: ...

    @abstractmethod
    def p_branch_relevant(self, t_cond: bool) -> bool: ...


# ------------------------------------------------------------------
# WDM LPE taint policy
# ------------------------------------------------------------------

_TAINTED_SOURCES = frozenset({
    "SystemBuffer", "Type3InputBuffer", "MdlAddress", "UserBuffer",
    "InputBufferLength", "OutputBufferLength", "IoControlCode",
    "InBufferSize", "OutBufferSize",
})

_UNTAINTED_SOURCES = frozenset({
    "Irp", "IRP", "DeviceObject", "DriverObject", "FileObject",
    "DeviceExtension", "Context",
})

_WRITE_SINKS = frozenset({
    "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory",
    "RtlCopyBytes", "RtlFillMemory", "RtlZeroMemory",
    "memmove_s", "memcpy_s", "memset",
    "ProbeAndReadUlong", "ProbeForWrite", "ProbeForRead",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "ExAllocatePoolWithTag", "ExAllocatePool2",
})


class WdmLpePolicy(TaintPolicy):
    """Taint policy for WDM/KMDF local privilege escalation analysis."""

    def p_input(self, source: str, context: dict | None = None) -> bool:
        """True if source entity is attacker-controlled."""
        # Direct match on known tainted sources
        if source in _TAINTED_SOURCES:
            return True
        # Known untainted
        if source in _UNTAINTED_SOURCES:
            return False
        # Heuristic: buffer-derived names
        src_lower = source.lower()
        if any(tag in src_lower for tag in ("inbuf", "outbuf", "userbuf", "systembuffer")):
            return True
        # Context-based check
        if context is not None:
            origin = context.get("origin", "")
            if any(tag in origin for tag in ("inbuf", "outbuf", "userbuf")):
                return True
        return False

    def p_const(self) -> bool:
        return False

    def p_binop(self, t1: bool, t2: bool) -> bool:
        return t1 or t2

    def p_mem_read(self, t_addr: bool, t_value: bool) -> bool:
        # Conservative: tainted if either address or value is tainted
        return t_addr or t_value

    def p_sink_check(self, sink_name: str, tainted_args: list[bool]) -> bool:
        """True if any arg is tainted for write-class sinks."""
        if sink_name in _WRITE_SINKS:
            return any(tainted_args)
        # Default: any tainted arg makes the call taint-relevant
        return any(tainted_args)

    def p_branch_relevant(self, t_cond: bool) -> bool:
        return t_cond


# ------------------------------------------------------------------
# build_tainted_set
# ------------------------------------------------------------------

def build_tainted_set(
    finding: dict,
    chain_facts: list[dict | None],
    symbol_table: SymbolTable,
    node_ea: str,
    policy: TaintPolicy,
) -> frozenset[str]:
    """Walk taint_chain entries to compute the set of tainted symbols at a node."""
    tainted: set[str] = set()

    for tc_entry in finding.get("taint_chain", []):
        caller = tc_entry.get("caller", {})
        caller_ea = caller.get("ea", "").lower()

        # Only process entries relevant to this node
        if caller_ea != node_ea:
            continue

        # Tainted entities from new_caller_taint
        new_taint = tc_entry.get("new_caller_taint", {})
        for entity in new_taint.get("tainted_entities", []):
            scoped = scoped_name(entity, caller_ea)
            # Check if this entity should be tainted per policy
            bare = entity.removeprefix("caller.").removeprefix("callee.")
            ctx = None
            sym = symbol_table.get(scoped)
            if sym is not None:
                ctx = {"origin": sym.origin, "domain": sym.domain}
            if policy.p_input(bare, ctx):
                tainted.add(scoped)

        # Taint mappings propagation
        for mapping in tc_entry.get("taint_mappings", []):
            map_from = mapping.get("from", "")
            map_to = mapping.get("to", "")
            transform = mapping.get("transform", "none")

            if not map_from:
                continue

            from_scoped = scoped_name(map_from, caller_ea)
            bare_from = map_from.removeprefix("caller.").removeprefix("callee.")

            # Check if source is tainted
            is_tainted = from_scoped in tainted or policy.p_input(bare_from)

            if is_tainted and map_to:
                to_scoped = scoped_name(map_to, caller_ea)
                if transform in ("none", "cast"):
                    tainted.add(to_scoped)
                elif transform == "deref":
                    # Memory read: check policy
                    if policy.p_mem_read(True, True):
                        tainted.add(to_scoped)
                elif transform == "offset":
                    # Pointer arithmetic: binop rule
                    if policy.p_binop(True, False):
                        tainted.add(to_scoped)

    return frozenset(tainted)


# ------------------------------------------------------------------
# validate_taint_chain
# ------------------------------------------------------------------

def validate_taint_chain(
    finding: dict,
    chain_facts: list[dict | None],
    symbol_table: SymbolTable,
    policy: TaintPolicy,
) -> list[TaintDiagnostic]:
    """Validate taint chain entries against taint policy.

    Returns list of TaintDiagnostic for overtaint/undertaint issues.
    """
    diagnostics: list[TaintDiagnostic] = []

    for tc_entry in finding.get("taint_chain", []):
        caller = tc_entry.get("caller", {})
        caller_ea = caller.get("ea", "").lower()

        # Check tainted entities
        new_taint = tc_entry.get("new_caller_taint", {})
        for entity in new_taint.get("tainted_entities", []):
            bare = entity.removeprefix("caller.").removeprefix("callee.")
            scoped = scoped_name(entity, caller_ea)

            ctx = None
            sym = symbol_table.get(scoped)
            if sym is not None:
                ctx = {"origin": sym.origin, "domain": sym.domain}

            should_be_tainted = policy.p_input(bare, ctx)

            if not should_be_tainted:
                # Chain claims tainted but policy disagrees -> overtaint
                diagnostics.append(TaintDiagnostic(
                    symbol_name=scoped,
                    source_ea=caller_ea,
                    diagnosis="overtaint",
                    reason=f"entity '{bare}' marked tainted but policy says untainted",
                    chain_confidence=tc_entry.get("confidence", 1.0),
                ))

        # Check taint mappings
        for mapping in tc_entry.get("taint_mappings", []):
            map_from = mapping.get("from", "")
            map_to = mapping.get("to", "")
            transform = mapping.get("transform", "none")

            if not (map_from and map_to):
                continue

            bare_from = map_from.removeprefix("caller.").removeprefix("callee.")
            from_scoped = scoped_name(map_from, caller_ea)

            # Source should be tainted for this mapping to matter
            source_tainted = policy.p_input(bare_from)

            if not source_tainted:
                # Check if the source is in the explicitly-untainted set
                if bare_from in _UNTAINTED_SOURCES:
                    diagnostics.append(TaintDiagnostic(
                        symbol_name=from_scoped,
                        source_ea=caller_ea,
                        diagnosis="overtaint",
                        reason=f"taint mapping from '{bare_from}' which is kernel-internal",
                        chain_confidence=tc_entry.get("confidence", 1.0),
                    ))

    return diagnostics
