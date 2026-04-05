"""Symbol table construction for SMT stage (Steps 5 & 6).

Deterministic, no LLM, no IDA -- runs at SMT stage time (out-of-process).

Step 5: Root symbols (ioctl_code, in_len, out_len, buffer bases).
Step 6: Buffer field registry with overlap constraint generation.

The SymbolTableBuilder consumes finding JSON + chain_facts + metas and
produces a SymbolTable that Steps 7-8 (constraint extraction) reference.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING
import ctypes

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from analysis.taint_results import TaintDiagnostic

from analysis.ir_schema import (
    Constraint,
    ConstraintKind,
    Expr,
    ExprOp,
    SourceInfo,
    Symbol,
    fresh,
    sym,
    ir_to_dict,
)

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

# Target endianness — x86/x64 is always little-endian
TARGET_ENDIAN = "little"


def _infer_signedness_from_type(type_str: str) -> bool | None:
    """Infer signedness from a type string. Unsigned check first (ULONG before LONG)."""
    upper = type_str.upper().strip().lstrip("_")
    if any(kw in upper for kw in ("UNSIGNED", "UINT", "ULONG", "UCHAR", "USHORT", "SIZE_T", "BOOLEAN")):
        return False
    if any(kw in upper for kw in ("SIGNED", "NTSTATUS")):
        return True
    # Bare INT/LONG/SHORT/CHAR — signed in C
    if any(kw in upper for kw in ("LONG", "SHORT", "CHAR", "INT")):
        return True
    return None


def _buf_short_name(buffer_symbol: str) -> str:
    """'inbuf_base' -> 'inbuf', 'userbuf_base' -> 'userbuf', etc."""
    return buffer_symbol.removesuffix("_base")


class DriverModel(str, Enum):
    Unknown = "Unknown"
    WDM = "WDM"
    WDF_KMDF = "WDF_KMDF"
    WDF_UMDF = "WDF_UMDF"


class BufferMethod(str, Enum):
    SYSTEM_BUFFER = "system_buffer"
    USER_BUFFER = "user_buffer"
    MDL = "mdl"
    KMDF_INPUT = "kmdf_input"
    KMDF_OUTPUT = "kmdf_output"
    Unknown = "Unknown"


# Width inference from IDA type strings (used for taint entity → field linking)
_TAINT_TYPE_WIDTH: dict[str, int] = {
    "BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8,
    "UCHAR": 1, "CHAR": 1, "BOOLEAN": 1,
    "USHORT": 2, "SHORT": 2,
    "ULONG": 4, "LONG": 4, "INT": 4, "UINT": 4,
    "ULONGLONG": 8, "LONGLONG": 8,
    "PHYSICAL_ADDRESS": 8, "LARGE_INTEGER": 8, "PVOID": 8,
    "SIZE_T": 8, "ULONG_PTR": 8,
    "__int64": 8, "__int32": 4, "__int16": 2, "__int8": 1,
    "char": 1, "short": 2, "int": 4, "long": 4,
}


def _infer_width_from_type(type_str: str) -> int | None:
    """Infer memory access width in bytes from a type string."""
    stripped = type_str.strip().lstrip("_")
    if stripped in _TAINT_TYPE_WIDTH:
        return _TAINT_TYPE_WIDTH[stripped]
    for kw, width in _TAINT_TYPE_WIDTH.items():
        if kw in type_str:
            return width
    return None


# ------------------------------------------------------------------
# FieldRegistry (Step 6 core)
# ------------------------------------------------------------------

@dataclass
class LayoutReport:
    """Per-buffer layout analysis result."""

    buffer_symbol: str
    total_bytes_accessed: int
    max_offset: int
    field_count: int
    overlapping_pairs: int
    coverage_gaps: list[tuple[int, int]]


@dataclass
class FieldAccess:
    """A single resolved buffer field: (buffer, offset, width)."""

    buffer_symbol: str  # e.g. "inbuf_base"
    offset: int         # byte offset from buffer start
    width: int          # access width in bytes (1, 2, 4, 8)
    symbol: Symbol      # the generated Symbol
    signed: bool | None = None  # None=unknown


@dataclass
class FieldRegistry:
    """Track buffer field symbols and generate overlap constraints.

    Naming convention:
        {buf_short}_{type_tag}_{hex_offset}
        e.g.  inbuf_u32_0x10, outbuf_u8_0x0, userbuf_u64_0x20

    Type tags: u8, u16, u32, u64 (unsigned bitvectors by width).
    """

    _accesses: dict[str, FieldAccess] = field(default_factory=dict)

    WIDTH_TAG: dict[int, str] = field(
        default_factory=lambda: {1: "u8", 2: "u16", 4: "u32", 8: "u64"},
        repr=False,
    )

    def register_field(self, buffer_symbol: str, offset: int, width: int,
                       signed: bool | None = None) -> Symbol:
        """Register a field and return its Symbol (idempotent).

        If (buffer, offset, width) was already registered, returns existing symbol.
        """
        buf_short = _buf_short_name(buffer_symbol)
        tag = self.WIDTH_TAG.get(width, f"u{width * 8}")
        name = f"{buf_short}_{tag}_0x{offset:x}"

        if name in self._accesses:
            return self._accesses[name].symbol

        sym = Symbol(
            name=name,
            sort=int,
            bitwidth=width * 8,
            domain="buffer_field",
            origin=f"{buffer_symbol}.{tag}@0x{offset:x}",
            signed=signed,
        )
        self._accesses[name] = FieldAccess(
            buffer_symbol=buffer_symbol,
            offset=offset,
            width=width,
            symbol=sym,
            signed=signed,
        )
        return sym

    def get_structural_constraints(self, node_ea: str) -> list[Constraint]:
        """Field overlap constraints are now handled by auto-linking in translate_to_z3.

        Each field is linked to per-buffer mem8 reads (c_field_link_* constraints).
        Overlapping fields share the same mem8 bytes, so Z3 infers equality
        automatically. Returns empty list — kept for API compatibility.
        """
        return []

    def get_layout_report(self) -> list["LayoutReport"]:
        """Analyze field layout per buffer. For diagnostics, not constraint generation."""
        reports: list[LayoutReport] = []
        by_buffer: dict[str, list[FieldAccess]] = {}
        for fa in self._accesses.values():
            by_buffer.setdefault(fa.buffer_symbol, []).append(fa)

        for buf_sym, accesses in by_buffer.items():
            accessed_bytes: set[int] = set()
            for fa in accesses:
                for i in range(fa.width):
                    accessed_bytes.add(fa.offset + i)

            # Count overlapping pairs
            overlaps = 0
            sorted_acc = sorted(accesses, key=lambda a: a.offset)
            for i, a in enumerate(sorted_acc):
                for j in range(i + 1, len(sorted_acc)):
                    b = sorted_acc[j]
                    if b.offset < a.offset + a.width:
                        overlaps += 1
                    else:
                        break

            # Find coverage gaps
            gaps: list[tuple[int, int]] = []
            if accessed_bytes:
                sorted_bytes = sorted(accessed_bytes)
                for k in range(1, len(sorted_bytes)):
                    if sorted_bytes[k] > sorted_bytes[k - 1] + 1:
                        gaps.append((sorted_bytes[k - 1] + 1, sorted_bytes[k]))

            reports.append(LayoutReport(
                buffer_symbol=buf_sym,
                total_bytes_accessed=len(accessed_bytes),
                max_offset=max(accessed_bytes) if accessed_bytes else 0,
                field_count=len(accesses),
                overlapping_pairs=overlaps,
                coverage_gaps=gaps,
            ))
        return reports


class UnionFind:
    """Union-find (disjoint set) for symbol name equivalences.

    Replaces dict[str, str] alias chains with O(α(n)) ≈ O(1) find/union.
    Path compression + union-by-rank. Backward-compatible dict-like API.
    """

    def __init__(self):
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, name: str) -> str:
        """Find canonical representative with path compression."""
        if name not in self._parent:
            return name
        root = name
        while self._parent[root] != root:
            root = self._parent[root]
        while name != root:
            next_parent = self._parent[name]
            self._parent[name] = root
            name = next_parent
        return root

    def union(self, alias: str, canonical: str) -> bool:
        """Make alias equivalent to canonical. Canonical's root wins."""
        root_alias = self.find(alias)
        root_canon = self.find(canonical)
        if root_alias == root_canon:
            return True
        self._parent.setdefault(root_alias, root_alias)
        self._parent.setdefault(root_canon, root_canon)
        self._rank.setdefault(root_alias, 0)
        self._rank.setdefault(root_canon, 0)
        self._parent[root_alias] = root_canon
        if self._rank[root_alias] == self._rank[root_canon]:
            self._rank[root_canon] += 1
        return True

    def __contains__(self, name: str) -> bool:
        """Check if name has been involved in any aliasing (as source or target)."""
        return name in self._parent

    def __getitem__(self, name: str) -> str:
        """Direct parent lookup (backward compat)."""
        return self._parent.get(name, name)

    def items(self) -> list[tuple[str, str]]:
        """All (alias, canonical) pairs — fully resolved."""
        result = []
        for name in list(self._parent):
            root = self.find(name)
            if name != root:
                result.append((name, root))
        return result

    def keys(self):
        """All alias names (non-root members)."""
        return [name for name in self._parent if self.find(name) != name]

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return sum(1 for name in self._parent if self.find(name) != name)

    def to_dict(self) -> dict[str, str]:
        """Flattened alias dict for serialization."""
        return dict(self.items())


@dataclass
class SymbolTable:
    """Central symbol table for one finding's SMT analysis.

    symbols: Symbol -> Expr (key is name-hashable Symbol, value is ASSIGN/SYMBOL Expr for that symbol).
    """

    symbols: dict[Symbol, Expr] = field(default_factory=dict)
    aliases: UnionFind = field(default_factory=UnionFind)
    fields: FieldRegistry = field(default_factory=FieldRegistry)
    structural_constraints: list[Constraint] = field(default_factory=list)
    driver_model: DriverModel = field(default=DriverModel.Unknown)
    buffer_methods: list[BufferMethod] = field(default_factory=list)
    _suspect_annotations: dict[str, "TaintDiagnostic"] = field(default_factory=dict)

    def add(self, expr_or_sym: Expr | Symbol, *, sort: type = int, domain: str = "") -> None:
        """Add a symbol by Expr or Symbol."""
        if isinstance(expr_or_sym, Symbol):
            s = expr_or_sym
            self.symbols[s] = Expr(op=ExprOp.SYMBOL, symbol=s.name, bitwidth=s.bitwidth)
            return
        name = expr_or_sym.symbol or ""
        for existing in list(self.symbols):
            if existing.name == name:
                del self.symbols[existing]
                break
        sym = Symbol(name=name, sort=int, bitwidth=expr_or_sym.bitwidth or 64)
        self.symbols[sym] = expr_or_sym

    def get(self, name: str) -> Expr | None:
        canonical = self.aliases.find(name)
        for sym, expr in self.symbols.items():
            if sym.name == canonical:
                return expr
        return None

    def add_alias(self, alias: str, canonical: str) -> None:
        self.aliases.union(alias, canonical)

    def mark_suspect(self, sym_name: str, diag) -> None:
        resolved = self.aliases.find(sym_name)
        self._suspect_annotations[resolved] = diag

    def get_suspect(self, sym_name: str):
        resolved = self.aliases.find(sym_name)
        return self._suspect_annotations.get(resolved)

    def is_overtaint_suspect(self, sym_name: str) -> bool:
        diag = self.get_suspect(sym_name)
        return diag is not None and getattr(diag, "diagnosis", None) == "overtaint"

    def define_sym(self, name: str, expr: Expr, line: int) -> None:
        logger.info("SymbolTable define name=%s line=%d", name, line)
        for existing in list(self.symbols):
            if existing.name == name:
                del self.symbols[existing]
                break
        sym = Symbol(name=name, sort=int, bitwidth=expr.bitwidth or 64)
        self.symbols[sym] = expr

    def resolve(self, name: str, at_line: int) -> Expr:
        logger.info("SymbolTable resolve name=%s at_line=%d", name, at_line)
        out = self.get(name)
        return out if out is not None else sym(name, 64)

    def new_fresh_sym(self, name: str, bw: int, ref: SourceInfo) -> Expr:
        key = name if name.startswith("_fresh_") else f"_fresh_{name}"
        for sym, expr in self.symbols.items():
            if sym.name == key:
                return expr
        sym = Symbol(name=key, sort=int, bitwidth=bw)
        self.symbols[sym] = fresh(key, bw, ref)
        return self.symbols[sym]

    def rename_fresh_to(self, old_name: str, new_name: str, define_for: str | None, line: int) -> None:
        old_sym = next((s for s in self.symbols if s.name == old_name), None)
        if old_sym is None:
            return
        old_expr = self.symbols.pop(old_sym)
        new_expr = Expr(
            old_expr.op,
            old_expr.args,
            old_expr.literal,
            new_name,
            old_expr.bitwidth,
            old_expr.ref,
        )
        new_sym = Symbol(name=new_name, sort=int, bitwidth=old_expr.bitwidth or 64)
        self.symbols[new_sym] = new_expr
        if define_for:
            for s in list(self.symbols):
                if s.name == define_for:
                    del self.symbols[s]
                    break
            self.symbols[Symbol(name=define_for, sort=int, bitwidth=new_expr.bitwidth or 64)] = new_expr
        logger.info("SymbolTable rename_fresh %s -> %s define_for=%s", old_name, new_name, define_for)

    def all_fresh_vars(self) -> list[Expr]:
        return [e for s, e in self.symbols.items() if "_fresh_" in s.name]

    def snapshot(self) -> dict[str, Expr]:
        return {s.name: e for s, e in self.symbols.items()}

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "driver_model": self.driver_model.value,
            "buffer_methods": [m.value for m in self.buffer_methods],
            "symbols": {s.name: ir_to_dict(expr) for s, expr in self.symbols.items()},
            "aliases": self.aliases.to_dict(),
            "fields": {
                name: {
                    "buffer_symbol": fa.buffer_symbol,
                    "offset": fa.offset,
                    "width": fa.width,
                }
                for name, fa in self.fields._accesses.items()
            },
            "structural_constraints": [ir_to_dict(c) for c in self.structural_constraints],
        }

    @classmethod
    def from_dict(cls, d: dict) -> SymbolTable:
        """Reconstruct a SymbolTable from a dict."""
        symbols: dict[Symbol, Expr] = {}
        for name, sd in d.get("symbols", {}).items():
            if sd.get("_type") == "Symbol":
                s = Symbol.from_dict(sd)
                symbols[s] = Expr(op=ExprOp.SYMBOL, symbol=s.name, bitwidth=s.bitwidth)
            else:
                expr = Expr.from_dict(sd)
                sym = Symbol(name=expr.symbol or name, sort=int, bitwidth=expr.bitwidth or 64)
                symbols[sym] = expr
        fields = FieldRegistry()
        for name, fd in d.get("fields", {}).items():
            field_sym = fields.register_field(fd["buffer_symbol"], fd["offset"], fd["width"])
            symbols[field_sym] = Expr(op=ExprOp.SYMBOL, symbol=field_sym.name, bitwidth=field_sym.bitwidth)
        uf = UnionFind()
        for alias, canonical in d.get("aliases", {}).items():
            uf.union(alias, canonical)
        raw_sc = d.get("structural_constraints", d.get("overlap_constraints", []))
        structural = [Constraint.from_dict(cd) for cd in raw_sc]
        return cls(
            symbols=symbols,
            aliases=uf,
            fields=fields,
            driver_model=DriverModel(d.get("driver_model", "Unknown")),
            buffer_methods=[BufferMethod(m) for m in d.get("buffer_methods", [])],
            structural_constraints=structural,
        )


# ------------------------------------------------------------------
# SymbolTableBuilder
# ------------------------------------------------------------------

class SymbolTableBuilder:
    """Deterministic symbol table construction from finding artifacts.

    Consumes: finding JSON dict, chain_facts list, metas dict.
    Produces: SymbolTable with root symbols, buffer bases, taint variables, field stubs.

    No LLM, no IDA -- runs at SMT stage time (out-of-process).
    """

    def __init__(
        self,
        finding: dict,
        chain_facts: list[dict | None],
        metas: dict[str, dict]
    ):
        self._finding = finding
        self._chain_facts = chain_facts
        self._metas = metas
        self.table = SymbolTable()
        self._deferred_aliases: list[tuple[str, str, str]] = []

    def build(self) -> SymbolTable:
        # NON-PLATFORM SPECIFIC
        self._add_root_symbols(self.table)
        self._add_prototype_symbols(self.table)
        self._add_taint_var_symbols(self.table)
        self._propagate_buffer_base_aliases(self.table)
        self._link_taint_entities_to_fields(self.table)
        self._resolve_deferred_aliases(self.table)
        self._detect_driver_model(self.table)

        # Driver I/O semantics: buffer symbols, aliases, provenance constraints
        logger.info("driver_io plugin disabled (ctree_to_ir removed), skipping driver buffer constraints")

        self.table.finalize()

        # Pass-level metrics
        n_symbols = len(self.table.symbols)
        n_aliases = len(self.table.aliases)
        n_fields = len(self.table.fields._accesses)
        n_unresolved = len(self._deferred_aliases)
        logger.info(
            "[*] SymbolTable: %d symbols, %d aliases (%d unresolved), "
            "%d fields, model=%s, methods=%s",
            n_symbols, n_aliases, n_unresolved, n_fields,
            self.table.driver_model.value,
            [m.value for m in self.table.buffer_methods] or "none",
        )

        return self.table

    # -- Step 5: Root environment symbols --

    def _add_root_symbols(self, table: SymbolTable) -> None:
        """Create universal root environment symbols: ioctl_code, lengths.

        Buffer base symbols (inbuf_base, outbuf_base, etc.) are created by
        the driver_io plugin after driver model detection.
        """
        # IOCTL code (32-bit: ULONG on Windows, unsigned)
        table.add(Symbol(
            name="ioctl_code",
            sort=int,
            bitwidth=32,
            domain="ioctl_code",
            origin="root",
            signed=False,
        ))
        # Buffer lengths (32-bit: ULONG on Windows, unsigned)
        for name in ("in_len", "out_len"):
            table.add(Symbol(
                name=name,
                sort=int,
                bitwidth=32,
                domain="length",
                origin="root",
                signed=False,
            ))

    # -- Driver model detection (heuristic) --

    _WDM_KEYWORDS = frozenset({
        "IRP_MJ_DEVICE_CONTROL", "DriverObject->MajorFunction",
        "IO_STACK_LOCATION", "IoBuildDeviceIoControlRequest",
        "IoCallDriver", "IofCompleteRequest", "DeviceObject",
    })
    _KMDF_KEYWORDS = frozenset({
        "WdfRequestRetrieveInputBuffer", "WdfRequestRetrieveOutputBuffer",
        "WdfDeviceInitSetIoType", "WDFREQUEST", "EvtIoDeviceControl",
        "WDF_IO_QUEUE_CONFIG", "WdfIoQueueCreate",
    })

    def _detect_driver_model(self, table: SymbolTable) -> None:
        """Set driver_model based on prototype/chain_facts keywords."""
        all_text = ""
        for cf in self._chain_facts:
            if cf is None:
                continue
            proto = cf.get("function", {}).get("prototype_guess", "")
            all_text += " " + proto
            # Also scan call targets
            for call in cf.get("calls", []):
                all_text += " " + call.get("name", "")

        chain = self._finding.get("chain", [])
        for node in chain:
            all_text += " " + node.get("name", "")

        kmdf_hits = sum(1 for kw in self._KMDF_KEYWORDS if kw in all_text)
        wdm_hits = sum(1 for kw in self._WDM_KEYWORDS if kw in all_text)

        if kmdf_hits > wdm_hits:
            table.driver_model = DriverModel.WDF_KMDF
        elif wdm_hits > 0:
            table.driver_model = DriverModel.WDM

        # Buffer method detection from chain_facts indicators
        methods: list[BufferMethod] = []
        for cf in self._chain_facts:
            if cf is None:
                continue
            wdm = cf.get("wdm_indicators", {})
            if wdm.get("reads_systembuffer") and BufferMethod.SYSTEM_BUFFER not in methods:
                methods.append(BufferMethod.SYSTEM_BUFFER)
            if wdm.get("reads_userbuffer") and BufferMethod.USER_BUFFER not in methods:
                methods.append(BufferMethod.USER_BUFFER)
            if wdm.get("reads_mdl") and BufferMethod.MDL not in methods:
                methods.append(BufferMethod.MDL)
            kmdf = cf.get("kmdf_indicators", {})
            if kmdf.get("calls_wdf_retrieve_input") and BufferMethod.KMDF_INPUT not in methods:
                methods.append(BufferMethod.KMDF_INPUT)
            if kmdf.get("calls_wdf_retrieve_output") and BufferMethod.KMDF_OUTPUT not in methods:
                methods.append(BufferMethod.KMDF_OUTPUT)
        table.buffer_methods = methods

    _RE_TAINT_FIELD = re.compile(
    r'\*\s*\(\s*\w+\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
    )
    _RE_PARAM = re.compile(r'(\w+)\s*(?=[,)])')
    # Matches "TYPE [*] NAME" in param lists. Group 1 = type tokens, group 2 = name.
    # Handles: "__int64 a1", "IRP *a2", "unsigned __int16 *a1", "_DRIVER_OBJECT *DriverObject"
    _RE_TYPED_PARAM = re.compile(r'(?:[(,])\s*([\w\s*]+?\s*\*?\s*)\s*(\w+)\s*(?=[,)])')

    _PARAM_TYPE_KEYWORDS = frozenset({
        "int", "void", "char", "short", "long",
        "PVOID", "HANDLE", "NTSTATUS", "BOOLEAN",
        "__int64", "__int32", "__int16", "__int8",
        "__fastcall", "__stdcall", "__cdecl",
        "unsigned", "signed", "const", "struct",
    })

    _RE_POINTER_BASE = re.compile(
        r'\*\s*\(\s*[^)]+?\s*\*\s*\)\s*\(\s*([\w.]+)\s*\+'
    )

    # -- Step 5d-post3: Link taint entity symbols to buffer fields --

    _RE_TAINT_ENTITY_FIELD = re.compile(
        r'\*\s*\(\s*([^)]+?)\s*\*\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
    )

    # -- Step 5d: Taint variable symbols --

    def _add_taint_var_symbols(self, table: SymbolTable) -> None:
        for tc_entry in self._finding.get("taint_chain", []):
            caller = tc_entry.get("caller", {})
            callee = tc_entry.get("callee", {})
            caller_ea = caller.get("ea", "").lower()
            callee_ea = callee.get("ea", "").lower()

            # Tainted entities in caller scope
            new_taint = tc_entry.get("new_caller_taint", {})
            if new_taint:
                for entity in new_taint.get("tainted_entities", []):
                    sym_name = scoped_name(entity, caller_ea)
                    table.add(Symbol(
                        name=sym_name,
                        sort=int,
                        bitwidth=64,
                        domain="taint_var",
                        origin=f"taint_chain:{caller_ea}",
                    ))
                    # Bare name alias: strip caller./callee. prefix
                    if entity.startswith("caller."):
                        bare = entity.removeprefix("caller.")
                        table.add_alias(scoped_name(bare, caller_ea), sym_name)
                    elif entity.startswith("callee."):
                        bare = entity.removeprefix("callee.")
                        table.add_alias(scoped_name(bare, caller_ea), sym_name)

            # Taint mappings: cross-boundary aliases
            for mapping in tc_entry.get("taint_mappings", []):
                map_from = mapping.get("from", "")
                map_to = mapping.get("to", "")
                transform = mapping.get("transform", "none")

                if not (map_from and map_to):
                    continue

                # Create the from-side symbol scoped to CALLER (map_from
                # is an expression in the caller's pseudocode)
                from_sym_name = scoped_name(map_from, caller_ea)
                table.add(Symbol(
                    name=from_sym_name,
                    sort=int,
                    bitwidth=64,
                    domain="taint_var",
                    origin=f"taint_chain:{caller_ea}",
                ))

                # For identity/cast transforms, register alias
                if transform in ("none", "cast"):
                    to_sym_name = scoped_name(map_to, caller_ea)
                    # to in caller scope is alias of from in callee scope
                    table.add_alias(to_sym_name, from_sym_name)
                elif transform in ("deref", "offset"):
                    # Create target symbol (Step 8 refines to buffer_field)
                    to_sym_name = scoped_name(map_to, caller_ea)
                    table.add(Symbol(
                        name=to_sym_name,
                        sort=int,
                        bitwidth=64,
                        domain="taint_var",
                        origin=f"taint_chain:{caller_ea}",
                    ))

                # Cross-perspective alias: callee.X@caller_ea -> caller.X@callee_ea
                # Deferred: target symbol may not exist yet (order-dependent)
                if map_to.startswith("callee."):
                    param = map_to.removeprefix("callee.")
                    alias_src = scoped_name(map_to, caller_ea)
                    callee_side = scoped_name(f"caller.{param}", callee_ea)
                    bare_side = scoped_name(param, callee_ea)
                    self._deferred_aliases.append((alias_src, callee_side, bare_side))


    def _resolve_deferred_aliases(self, table: SymbolTable) -> None:
        """Fixpoint: resolve deferred cross-boundary aliases."""
        max_rounds = 5
        for _ in range(max_rounds):
            remaining = []
            for alias_src, preferred, fallback in self._deferred_aliases:
                if table.get(preferred) is not None:
                    table.add_alias(alias_src, preferred)
                elif table.get(fallback) is not None:
                    table.add_alias(alias_src, fallback)
                else:
                    remaining.append((alias_src, preferred, fallback))
            if len(remaining) == len(self._deferred_aliases):
                break  # no progress
            self._deferred_aliases = remaining
        if self._deferred_aliases:
            for src, pref, fb in self._deferred_aliases:
                logger.debug("unresolved deferred alias: %s -> %s / %s", src, pref, fb)

    def _link_taint_entities_to_fields(self, table: SymbolTable) -> None:
        """Link taint entity symbols like *(TYPE*)(base + offset) to buffer fields.

        If the base resolves to a *_base pointer, the entity represents the
        same value as the corresponding buffer field symbol.  Register the
        field (idempotent) and alias the entity to it.
        """
        for sym in list(table.symbols):
            sym_name = sym.name
            if sym.domain != "taint_var":
                continue
            sn = parse_scoped(sym_name)
            if not sn.is_scoped:
                continue

            entity_name, ea = sn.base, sn.ea
            m = self._RE_TAINT_ENTITY_FIELD.match(entity_name)
            if not m:
                continue

            type_str = m.group(1)
            base_name = m.group(2)
            offset_str = m.group(3)
            offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)

            base_scoped = scoped_name(base_name, ea)
            if table.get(base_scoped) is None or not base_name.endswith("_base"):
                continue
            base_sym = next((s for s, _ in table.symbols.items() if s.name == base_scoped), None)
            if base_sym is None or base_sym.domain != "pointer":
                continue

            width = _infer_width_from_type(type_str)
            if width is None:
                continue

            field_sym = table.fields.register_field(base_name, offset, width)
            if table.get(field_sym.name) is None:
                table.add(Expr(op=ExprOp.SYMBOL, symbol=field_sym.name, bitwidth=field_sym.bitwidth))

            table.add_alias(sym_name, field_sym.name)

                
    # -- Step 5d-pre: Prototype parameter symbols --


    def _add_prototype_symbols(self, table: SymbolTable) -> None:
        """Create symbols for function parameters from prototype_guess.

        Uses typed regex to infer bitwidths from type tokens (e.g. char -> 8,
        __int16 -> 16, pointer -> 64). Falls back to name-only regex with 64-bit default.
        """
        chain = self._finding.get("chain", [])
        for i, node in enumerate(chain):
            if i >= len(self._chain_facts) or self._chain_facts[i] is None:
                continue
            cf = self._chain_facts[i]
            func_info = cf.get("function", {})
            proto = func_info.get("prototype_guess", "")
            ea = node["ea"].lower()

            if not proto:
                continue

            paren_start = proto.find("(")
            if paren_start < 0:
                continue
            param_str = proto[paren_start:]

            # Try typed regex first (extracts type + name)
            found_typed = False
            for m in self._RE_TYPED_PARAM.finditer(param_str):
                found_typed = True
                type_part = m.group(1).strip()
                param_name = m.group(2)
                if param_name in self._PARAM_TYPE_KEYWORDS:
                    continue

                is_pointer = "*" in type_part
                if is_pointer:
                    bitwidth = 64
                    is_signed = False  # pointers are unsigned
                else:
                    width_bytes = _infer_width_from_type(type_part)
                    bitwidth = (width_bytes * 8) if width_bytes else 64
                    is_signed = _infer_signedness_from_type(type_part)

                scoped = scoped_name(param_name, ea)
                if table.get(scoped) is None:
                    table.add(Symbol(
                        name=scoped,
                        sort=int,
                        bitwidth=bitwidth,
                        domain="taint_var",
                        origin=f"prototype:{ea}",
                        signed=is_signed,
                    ))

            # Fallback: name-only regex with 64-bit default
            if not found_typed:
                for m in self._RE_PARAM.finditer(param_str):
                    param_name = m.group(1)
                    if param_name in self._PARAM_TYPE_KEYWORDS:
                        continue
                    scoped = scoped_name(param_name, ea)
                    if table.get(scoped) is None:
                        table.add(Symbol(
                            name=scoped,
                            sort=int,
                            bitwidth=64,
                            domain="taint_var",
                            origin=f"prototype:{ea}",
                        ))


    # -- Step 5d-post2: Propagate buffer base aliases across call boundaries --

    def _propagate_buffer_base_aliases(self, table: SymbolTable) -> None:
        """Alias caller-side pointer bases to buffer bases via taint mappings.

        If a taint_mapping has *(TYPE*)(FROM_BASE + off) -> *(TYPE*)(TO_BASE + off)
        and TO_BASE (in callee scope) resolves to a *_base symbol, then
        FROM_BASE (in caller scope) should resolve to the same *_base.
        """
        for tc_entry in self._finding.get("taint_chain", []):
            caller_ea = tc_entry.get("caller", {}).get("ea", "").lower()
            callee_ea = tc_entry.get("callee", {}).get("ea", "").lower()

            for mapping in tc_entry.get("taint_mappings", []):
                map_from = mapping.get("from", "")
                map_to = mapping.get("to", "")
                if not (map_from and map_to):
                    continue

                m_from = self._RE_POINTER_BASE.search(map_from)
                m_to = self._RE_POINTER_BASE.search(map_to)
                if not (m_from and m_to):
                    continue

                from_base = m_from.group(1)
                to_base_raw = m_to.group(1)

                # Strip callee. prefix to get the callee parameter name
                to_param = (to_base_raw.removeprefix("callee.")
                            if to_base_raw.startswith("callee.") else to_base_raw)

                to_scoped = scoped_name(to_param, callee_ea)
                to_sym = table.get(to_scoped)
                if to_sym is None:
                    continue
                base_part = (to_sym.symbol or "").split("@")[0]
                if not base_part.endswith("_base"):
                    continue

                from_scoped = scoped_name(from_base, caller_ea)
                existing = table.get(from_scoped)
                if existing is not None:
                    existing_base = (existing.symbol or "").split("@")[0]
                    if existing_base.endswith("_base"):
                        continue

                if not any(s.name == from_scoped for s in table.symbols) and from_scoped not in table.aliases:
                    table.add(Symbol(
                        name=from_scoped,
                        sort=int,
                        bitwidth=64,
                        domain="taint_var",
                        origin=f"buffer_propagation:{caller_ea}",
                    ))
                table.add_alias(from_scoped, to_scoped)

