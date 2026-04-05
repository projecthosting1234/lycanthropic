"""Pipeline IR -> Z3 encoder (merged with IR-to-Z3 translator).

Converts pipeline constraints to IR, runs typecheck and translation
(TypecheckPass, Z3VarFactory, ExprTranslator), builds a solver from the result.
Preserves the incremental encoder API (add_constraint, check, get_ite_conds,
decode_path_from_model, add_path_blocker, get_model) for CEGAR refinement.

Module-level translate_to_z3(...) is the single entry point; Z3Encoder calls it
for its incremental batch path.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
import ctypes
import z3

from analysis.common.debug import logger
from analysis.ir_schema import (
    Constraint,
    Expr,
    ExprOp,
    ConstraintKind,
    Symbol,
    ir_to_dict,
)
from analysis.ir_to_z3.symbols import SymbolTable, TARGET_ENDIAN

# Constraints with confidence >= this threshold are treated as hard
HARD_CONFIDENCE_THRESHOLD = 0.7

# -----------------------------------------------------------------------
# MaxSMT weight computation
# -----------------------------------------------------------------------

_FACT_CLASS_WEIGHT: dict[str, int] = {
    "exact_mined": 100,
    "ctree_fact": 100,
    "ssa_structural": 80,
    "field_structural": 80,
    "environment": 60,
    "llm_hypothesis": 40,
    "concrete_weakened": 10,
    "": 30,
}

_TIER_MULTIPLIER: dict[int, float] = {0: 1.0, 1: 0.7, 2: 0.4}


def compute_weight(c: Constraint) -> int:
    """Compute MaxSMT weight for a soft constraint."""
    fc = c.fact_class.value if hasattr(c.fact_class, "value") else str(c.fact_class)
    base = _FACT_CLASS_WEIGHT.get(fc, 30)
    tier = _TIER_MULTIPLIER.get(c.model_tier, 0.5)
    return max(1, min(1000, int(round(base * tier * c.confidence))))


# -----------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------


class TranslationError(Exception):
    """Raised when an Expr cannot be translated to Z3."""


# -----------------------------------------------------------------------
# TypecheckPass
# -----------------------------------------------------------------------


class DiagLevel(str, Enum):
    WARNING = "warning"
    ERROR = "error"


@dataclass
class TypecheckDiagnostic:
    constraint_id: str
    level: DiagLevel
    message: str


_ARITY: dict[str, int | tuple[int, ...]] = {
    "bvadd": 2,
    "bvsub": 2,
    "bvmul": 2,
    "bvudiv": 2,
    "bvsdiv": 2,
    "bvurem": 2,
    "bvsrem": 2,
    "bvand": 2,
    "bvor": 2,
    "bvxor": 2,
    "bvshl": 2,
    "bvlshr": 2,
    "bvashr": 2,
    "eq": 2,
    "ne": 2,
    "assign": 2,
    "ult": 2,
    "ule": 2,
    "ugt": 2,
    "uge": 2,
    "slt": 2,
    "sle": 2,
    "sgt": 2,
    "sge": 2,
    "bveq": 2,
    "bvne": 2,
    "bvult": 2,
    "bvule": 2,
    "bvugt": 2,
    "bvuge": 2,
    "bvslt": 2,
    "bvsle": 2,
    "bvsgt": 2,
    "bvsge": 2,
    "and": (2,),
    "or": (2,),
    "not": 1,
    "ite": 3,
    "extract": 1,
    "concat": (2,),
    "zext": 1,
    "sext": 1,
    "deref": 1,
    "switch": (1,),
}

# Boolean comparison ops: result type boolean (typecheck returns None)
_BOOLEAN_CMP_OPS = frozenset(
    {
        "eq",
        "ne",
        "ult",
        "ule",
        "ugt",
        "uge",
        "slt",
        "sle",
        "sgt",
        "sge",
    }
)

# BV comparison ops: result type 1-bit BV (typecheck returns 1)
_BV_CMP_OPS = frozenset(
    {
        "bveq",
        "bvne",
        "bvult",
        "bvule",
        "bvugt",
        "bvuge",
        "bvslt",
        "bvsle",
        "bvsgt",
        "bvsge",
    }
)

_BOOLEAN_OPS = frozenset(
    {
        "eq",
        "ne",
        "ult",
        "ule",
        "ugt",
        "uge",
        "slt",
        "sle",
        "sgt",
        "sge",
        "and",
        "or",
        "not",
    }
)


def _expr_op_str(expr: Expr) -> str | None:
    """Return op as string for typecheck/translator."""
    if expr.op is None:
        return None
    return expr.op.value if isinstance(expr.op, ExprOp) else str(expr.op)


class TypecheckPass:
    """Validate and infer bitwidths in constraint Expr trees."""

    def __init__(self, constraints: list[Constraint], symbol_table: SymbolTable):
        self._constraints = constraints
        self._st = symbol_table
        self._diags: list[TypecheckDiagnostic] = []
        self._skip_ids: set[str] = set()

    def run(self) -> tuple[list[TypecheckDiagnostic], set[str]]:
        for c in self._constraints:
            self._current_cid = c.id
            self._check_expr(c.expr)
        return self._diags, self._skip_ids

    def _diag(self, level: DiagLevel, msg: str) -> None:
        self._diags.append(
            TypecheckDiagnostic(
                constraint_id=self._current_cid, level=level, message=msg
            )
        )

    def _error_skip(self, msg: str) -> None:
        self._diag(DiagLevel.ERROR, msg)
        self._skip_ids.add(self._current_cid)

    def _check_expr(self, expr: Expr) -> int | type:
        """Return type bool for boolean, or int bitwidth for BV. Types are first-class (bool, int stand-in for BV)."""
        if expr.literal is not None:
            if isinstance(expr.literal, bool):
                return bool
            if isinstance(expr.literal, int):
                bw = getattr(expr, "bitwidth", None) or 64
                max_val = (1 << bw) - 1
                if expr.literal > max_val:
                    self._diag(
                        DiagLevel.WARNING,
                        f"literal {expr.literal:#x} exceeds {bw}-bit range (Z3 will truncate)",
                    )
                return bw
            return 64

        # If this is a variable, return its bitwidth or "bool" for boolean.
        sym_name = expr.symbol
        if sym_name is not None:
            resolved = self._st.get(sym_name)
            if resolved is None:
                self._error_skip(f"undefined symbol: {sym_name}")
                return 64
            return resolved.bitwidth or 64

        op_str = _expr_op_str(expr)
        if op_str is None:
            self._error_skip("expr has no op, literal, or symbol")
            return 64

        expected = _ARITY.get(op_str)
        if expected is None:
            self._error_skip(f"unknown op: {op_str}")
            return 64

        n_args = len(expr.args)

        if op_str == "deref" and n_args == 2:
            expr = Expr(
                op=ExprOp.DEREF,
                args=(Expr(op=ExprOp.BVADD, args=expr.args),),
                bitwidth=expr.bitwidth,
                ref=expr.ref,
            )
            n_args = 1
            self._diag(
                DiagLevel.WARNING,
                "auto-repaired deref(base, offset) to deref(bvadd(base, offset))",
            )

        if isinstance(expected, tuple):
            if n_args < expected[0]:
                self._error_skip(
                    f"op '{op_str}' requires at least {expected[0]} args, got {n_args}"
                )
                return 64
        else:
            if n_args != expected:
                self._error_skip(
                    f"op '{op_str}' requires {expected} args, got {n_args}"
                )
                return 64

        if op_str == "extract":
            if expr.extract_hi is None or expr.extract_lo is None:
                self._error_skip("extract missing hi/lo indices")
                return 64
            if expr.extract_hi < expr.extract_lo or expr.extract_lo < 0:
                self._error_skip(
                    f"extract invalid range: [{expr.extract_hi}:{expr.extract_lo}]"
                )
                return 64
            arg_bw = self._check_expr(expr.args[0])
            if self._current_cid in self._skip_ids:
                return 64
            if arg_bw is bool:
                self._error_skip("extract requires BV operand, got boolean")
                return 64
            if expr.extract_hi >= arg_bw:
                self._error_skip(
                    f"extract hi={expr.extract_hi} >= arg bitwidth={arg_bw}"
                )
                return 64
            return expr.extract_hi - expr.extract_lo + 1

        if op_str in ("zext", "sext"):
            arg_bw = self._check_expr(expr.args[0])
            if self._current_cid in self._skip_ids:
                return 64
            if arg_bw is bool:
                self._error_skip(f"{op_str} requires BV operand, got boolean")
                return 64
            if expr.bitwidth is None:
                self._error_skip(f"{op_str} missing target bitwidth")
                return 64
            if expr.bitwidth < arg_bw:
                self._error_skip(f"{op_str} target {expr.bitwidth} < source {arg_bw}")
                return 64
            # target >= source: no-op when equal is valid (zext/sext that adds 0 bits)
            return expr.bitwidth

        if op_str == "ite":
            cond_bw = self._check_expr(expr.args[0])
            if self._current_cid in self._skip_ids:
                return 64
            if cond_bw is not bool:
                self._error_skip("ite condition is BV, requires boolean")
                return 64
            then_bw = self._check_expr(expr.args[1])
            if self._current_cid in self._skip_ids:
                return 64
            else_bw = self._check_expr(expr.args[2])
            if self._current_cid in self._skip_ids:
                return 64
            if (then_bw is bool) != (else_bw is bool):
                self._error_skip("ite branches have mixed types (bool vs BV)")
                return 64
            if then_bw is bool and else_bw is bool:
                return bool
            return max(bw for bw in (then_bw, else_bw) if bw is not bool)

        arg_bws: list[int | type] = []
        for arg in expr.args:
            bw = self._check_expr(arg)
            if self._current_cid in self._skip_ids:
                return 64
            arg_bws.append(bw)

        if op_str == "switch":
            if not arg_bws:
                self._error_skip("switch requires at least one target")
                return bool
            for i, bw in enumerate(arg_bws):
                if bw is bool:
                    self._error_skip(f"switch target {i} is boolean, requires BV")
                    return bool
            return bool

        for i, arg in enumerate(expr.args):
            if (
                arg.literal is not None
                and isinstance(arg.literal, int)
                and arg.bitwidth is None
            ):
                sibling_bw = None
                for j, other_bw in enumerate(arg_bws):
                    if j != i and isinstance(other_bw, int):
                        sibling_bw = other_bw
                        break
                if sibling_bw is not None:
                    arg.bitwidth = sibling_bw
                    arg_bws[i] = sibling_bw
                    self._diag(
                        DiagLevel.WARNING,
                        f"literal {arg.literal} bitwidth inferred as {sibling_bw} from sibling",
                    )
                else:
                    arg.bitwidth = 64
                    arg_bws[i] = 64
                    self._diag(
                        DiagLevel.WARNING,
                        f"literal {arg.literal} bitwidth defaulted to 64",
                    )

        if op_str in ("not", "and", "or"):
            return bool

        if op_str == "assign":
            if len(arg_bws) == 2:
                a_type, b_type = arg_bws[0], arg_bws[1]
                if (a_type is bool) != (b_type is bool):
                    self._error_skip("'assign' has mixed types (bool vs BV)")
                    return 64
            return bool

        if op_str in _BOOLEAN_CMP_OPS or op_str in _BV_CMP_OPS:
            if len(arg_bws) == 2:
                a_type, b_type = arg_bws[0], arg_bws[1]
                if (a_type is bool) != (b_type is bool):
                    self._error_skip(f"'{op_str}' has mixed types (bool vs BV)")
                    return 64
            return bool

        if op_str == "concat":
            for i, bw in enumerate(arg_bws):
                if bw is bool:
                    self._error_skip(f"concat arg {i} is boolean, requires BV")
                    return 64
            total = sum(bw for bw in arg_bws if isinstance(bw, int))
            return total if total > 0 else 64

        if op_str == "deref":
            if any(bw is bool for bw in arg_bws):
                self._error_skip("deref requires BV address operand, got boolean")
                return 64
            return expr.bitwidth or 64

        for i, bw in enumerate(arg_bws):
            if bw is bool:
                self._error_skip(f"'{op_str}' arg {i} is boolean, requires BV")
                return 64
        return max(bw for bw in arg_bws if isinstance(bw, int))


# -----------------------------------------------------------------------
# Z3VarFactory
# -----------------------------------------------------------------------


def _extract_buffer_base(expr: Expr, st: SymbolTable) -> str | None:
    sym_ref = expr.symbol
    if sym_ref is not None:
        canonical = st.aliases.find(sym_ref)
        for sym, _ in st.symbols.items():
            if sym.name == canonical:
                if sym.domain == "pointer":
                    name = sym.name
                    if "#" in name:
                        name = name.rsplit("#", 1)[0]
                    return name.removesuffix("_base")
                return None
        return None
    if _expr_op_str(expr) == "bvadd" and expr.args:
        return _extract_buffer_base(expr.args[0], st)
    return None


class Z3VarFactory:
    """Create and cache Z3 variables from symbol table lookups."""

    def __init__(self, symbol_table: SymbolTable):
        self._st = symbol_table
        self._cache: dict[str, z3.ExprRef] = {}
        self._deref_funcs: dict[tuple[int, int], z3.FuncDeclRef] = {}
        self._mem8_global: z3.FuncDeclRef | None = None
        self._mem8_per_buffer: dict[str, z3.FuncDeclRef] = {}

    def get_var(self, name: str) -> z3.ExprRef:
        canonical = self._resolve_name(name)
        if canonical in self._cache:
            return self._cache[canonical]
        for sym, expr in self._st.symbols.items():
            if sym.name == canonical:
                var_name = expr.symbol or sym.name
                if sym.sort is bool:
                    var = z3.Bool(var_name)
                elif sym.sort is int:
                    var = z3.BitVec(var_name, sym.bitwidth or expr.bitwidth or 64)
                else:
                    var = z3.BitVec(var_name, sym.bitwidth or expr.bitwidth or 64)
                self._cache[canonical] = var
                return var
        raise KeyError(f"Symbol not found: {name} (resolved to {canonical})")

    def get_deref_func(self, in_bw: int = 64, out_bw: int = 64) -> z3.FuncDeclRef:
        key = (in_bw, out_bw)
        if key in self._deref_funcs:
            return self._deref_funcs[key]
        func = z3.Function(
            f"deref_{in_bw}_{out_bw}", z3.BitVecSort(in_bw), z3.BitVecSort(out_bw)
        )
        self._deref_funcs[key] = func
        return func

    def get_buffer_mem8(self, buffer_name: str) -> z3.FuncDeclRef:
        if buffer_name not in self._mem8_per_buffer:
            self._mem8_per_buffer[buffer_name] = z3.Function(
                f"{buffer_name}_mem8", z3.BitVecSort(64), z3.BitVecSort(8)
            )
        return self._mem8_per_buffer[buffer_name]

    def get_mem8(self) -> z3.FuncDeclRef:
        if self._mem8_global is None:
            self._mem8_global = z3.Function("mem8", z3.BitVecSort(64), z3.BitVecSort(8))
        return self._mem8_global

    def _resolve_name(self, name: str) -> str:
        return self._st.aliases.find(name)

    @property
    def all_vars(self) -> dict[str, z3.ExprRef]:
        return dict(self._cache)

    @property
    def deref_functions(self) -> dict[str, z3.FuncDeclRef]:
        result = {f"deref_{k[0]}_{k[1]}": v for k, v in self._deref_funcs.items()}
        if self._mem8_global is not None:
            result["mem8"] = self._mem8_global
        for buf_name, func in self._mem8_per_buffer.items():
            result[f"{buf_name}_mem8"] = func
        return result


# -----------------------------------------------------------------------
# ExprTranslator
# -----------------------------------------------------------------------

_BINARY_ARITH: dict[str, object] = {
    "bvadd": lambda a, b: a + b,
    "bvsub": lambda a, b: a - b,
    "bvmul": lambda a, b: a * b,
    "bvudiv": z3.UDiv,
    "bvsdiv": lambda a, b: a / b,
    "bvurem": z3.URem,
    "bvsrem": z3.SRem,
}

_BINARY_BITWISE: dict[str, object] = {
    "bvand": lambda a, b: a & b,
    "bvor": lambda a, b: a | b,
    "bvxor": lambda a, b: a ^ b,
    "bvshl": lambda a, b: a << b,
    "bvlshr": z3.LShR,
    "bvashr": lambda a, b: a >> b,
}

# Canonical comparison: one Z3 op per semantic (boolean op names only).
_BINARY_CMP: dict[str, object] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "ult": z3.ULT,
    "ule": z3.ULE,
    "ugt": z3.UGT,
    "uge": z3.UGE,
    "slt": lambda a, b: a < b,
    "sle": lambda a, b: a <= b,
    "sgt": lambda a, b: a > b,
    "sge": lambda a, b: a >= b,
}
# BV comparison op -> same canonical key as boolean variant (no duplicate Z3 mapping).
_BV_CMP_TO_CANONICAL = {
    "bveq": "eq",
    "bvne": "ne",
    "bvult": "ult",
    "bvule": "ule",
    "bvugt": "ugt",
    "bvuge": "uge",
    "bvslt": "slt",
    "bvsle": "sle",
    "bvsgt": "sgt",
    "bvsge": "sge",
}

_SIGNED_OPS = frozenset(
    {"slt", "sle", "sgt", "sge", "bvslt", "bvsle", "bvsgt", "bvsge", "bvashr"}
)


class ExprTranslator:
    """Recursive Expr -> z3.ExprRef translation with automatic bitwidth coercion."""

    def __init__(self, var_factory: Z3VarFactory, symbol_table: SymbolTable):
        self._vf = var_factory
        self._st = symbol_table

    def translate(self, expr: Expr) -> z3.ExprRef:
        if expr.literal is not None:
            if isinstance(expr.literal, bool):
                return z3.BoolVal(expr.literal)
            bw = expr.bitwidth or 64
            return z3.BitVecVal(expr.literal, bw)
        sym_ref = expr.symbol
        if sym_ref is not None:
            return self._vf.get_var(sym_ref)
        if expr.op is None:
            raise TranslationError("Expr has no op, literal, or symbol")
        return self._translate_op(expr)

    def _translate_op(self, expr: Expr) -> z3.ExprRef:
        op = _expr_op_str(expr) or expr.op

        if op in _BINARY_ARITH:
            a, b = self.translate(expr.args[0]), self.translate(expr.args[1])
            a, b = self._coerce_pair(a, b)
            return _BINARY_ARITH[op](a, b)

        if op in _BINARY_BITWISE:
            a, b = self.translate(expr.args[0]), self.translate(expr.args[1])
            a, b = self._coerce_pair(a, b, signed=(op in _SIGNED_OPS))
            return _BINARY_BITWISE[op](a, b)

        if op == "assign":
            a, b = self.translate(expr.args[0]), self.translate(expr.args[1])
            a, b = self._coerce_pair(a, b)
            return a == b

        if op in _BOOLEAN_CMP_OPS or op in _BV_CMP_OPS:
            a, b = self.translate(expr.args[0]), self.translate(expr.args[1])
            signed = op in _SIGNED_OPS
            a, b = self._coerce_pair(a, b, signed=signed)
            canonical = _BV_CMP_TO_CANONICAL.get(op, op)
            cmp_result = _BINARY_CMP[canonical](a, b)  # Z3 Bool
            if op in _BV_CMP_OPS:
                return z3.If(cmp_result, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
            return cmp_result

        if op == "and":
            args = [self._ensure_bool(self.translate(a)) for a in expr.args]
            return z3.And(*args)
        if op == "or":
            args = [self._ensure_bool(self.translate(a)) for a in expr.args]
            return z3.Or(*args)
        if op == "not":
            arg = self._ensure_bool(self.translate(expr.args[0]))
            return z3.Not(arg)
        if op == "ite":
            cond = self._ensure_bool(self.translate(expr.args[0]))
            then_val = self.translate(expr.args[1])
            else_val = self.translate(expr.args[2])
            then_val, else_val = self._coerce_pair(then_val, else_val)
            return z3.If(cond, then_val, else_val)
        if op == "extract":
            arg = self.translate(expr.args[0])
            return z3.Extract(expr.extract_hi, expr.extract_lo, arg)
        if op == "concat":
            args = [self.translate(a) for a in expr.args]
            return z3.Concat(*args)
        if op == "zext":
            arg = self.translate(expr.args[0])
            extra = expr.bitwidth - arg.size()
            if extra <= 0:
                return arg if extra == 0 else z3.Extract(expr.bitwidth - 1, 0, arg)
            return z3.ZeroExt(extra, arg)
        if op == "sext":
            arg = self.translate(expr.args[0])
            extra = expr.bitwidth - arg.size()
            if extra <= 0:
                return arg if extra == 0 else z3.Extract(expr.bitwidth - 1, 0, arg)
            return z3.SignExt(extra, arg)
        if op == "deref":
            buffer_base = _extract_buffer_base(expr.args[0], self._st)
            arg = self.translate(expr.args[0])
            in_bw = arg.size() if z3.is_bv(arg) else 64
            out_bw = expr.bitwidth or 64
            n_bytes = out_bw // 8
            mem8 = (
                self._vf.get_buffer_mem8(buffer_base)
                if buffer_base is not None
                else self._vf.get_mem8()
            )
            if in_bw < 64:
                arg = z3.ZeroExt(64 - in_bw, arg)
            elif in_bw > 64:
                arg = z3.Extract(63, 0, arg)
            bytes_exprs = [mem8(arg + z3.BitVecVal(i, 64)) for i in range(n_bytes)]
            if len(bytes_exprs) == 1:
                return bytes_exprs[0]
            return z3.Concat(*reversed(bytes_exprs))

        if op == "switch":
            return z3.BoolVal(True)

        raise TranslationError(f"Unknown op: {op}")

    def _coerce_pair(
        self, a: z3.ExprRef, b: z3.ExprRef, *, signed: bool = False
    ) -> tuple[z3.ExprRef, z3.ExprRef]:
        if z3.is_int(a) and z3.is_bv(b):
            b = z3.BV2Int(b, is_signed=signed)
            return a, b
        if z3.is_bv(a) and z3.is_int(b):
            a = z3.BV2Int(a, is_signed=signed)
            return a, b
        if z3.is_int(a) and z3.is_int(b):
            return a, b
        if z3.is_bool(a) and z3.is_bool(b):
            return a, b
        if z3.is_bool(a) or z3.is_bool(b):
            raise TranslationError(f"Bool/BV mixing in _coerce_pair: a={a}, b={b}")
        _ext = z3.SignExt if signed else z3.ZeroExt
        aw, bw = a.size(), b.size()
        if aw < bw:
            a = _ext(bw - aw, a)
        elif bw < aw:
            b = _ext(aw - bw, b)
        return a, b

    def _ensure_bool(self, e: z3.ExprRef) -> z3.ExprRef:
        if z3.is_bv(e):
            return e != z3.BitVecVal(0, e.size())
        if z3.is_int(e):
            return e != z3.IntVal(0)
        return e


# -----------------------------------------------------------------------
# Z3TranslationResult and translate_to_z3
# -----------------------------------------------------------------------


@dataclass
class Z3TranslationResult:
    z3_vars: dict[str, z3.ExprRef]
    z3_exprs: dict[str, z3.ExprRef]
    hard_constraint_ids: list[str]
    soft_constraint_ids: list[str]
    soft_weights: dict[str, int] = field(default_factory=dict)
    skipped_constraints: list[tuple[str, str]] = field(default_factory=list)
    typecheck_diagnostics: list[TypecheckDiagnostic] = field(default_factory=list)
    translation_diagnostics: list[str] = field(default_factory=list)
    deref_functions: dict[str, z3.FuncDeclRef] = field(default_factory=dict)


# -----------------------------------------------------------------------
# Integrity validation
# -----------------------------------------------------------------------


@dataclass
class IntegrityResult:
    passed: bool
    skipped_hard_count: int = 0
    skipped_exact_count: int = 0
    undef_symbol_count: int = 0
    typecheck_error_count: int = 0
    typecheck_warning_count: int = 0
    total_constraints: int = 0
    violations: list[str] = field(default_factory=list)


def validate_translation_integrity(
    z3_result: Z3TranslationResult,
    all_constraints: list[Constraint],
) -> IntegrityResult:
    index = {c.id: c for c in all_constraints if c.id}
    result = IntegrityResult(passed=True, total_constraints=len(all_constraints))

    for cid, reason in z3_result.skipped_constraints:
        c = index.get(cid)
        if c is None:
            continue
        is_hard = not c.soft and c.confidence >= HARD_CONFIDENCE_THRESHOLD
        if is_hard:
            result.skipped_hard_count += 1
            result.violations.append("skipped hard constraint %s: %s" % (cid, reason))
            if is_exact(c) and c.model_tier == 0:
                result.skipped_exact_count += 1
        if "Symbol not found" in reason or "undefined symbol" in reason:
            result.undef_symbol_count += 1

    for diag in z3_result.typecheck_diagnostics:
        if diag.level == DiagLevel.ERROR:
            result.typecheck_error_count += 1
        elif diag.level == DiagLevel.WARNING:
            result.typecheck_warning_count += 1

    undef_ratio = (
        result.undef_symbol_count / result.total_constraints
        if result.total_constraints > 0
        else 0.0
    )
    result.passed = result.skipped_hard_count == 0 and undef_ratio <= 0.2

    if not result.passed:
        logger.info(
            "[!] Integrity: FAILED (hard_skipped=%d, exact_skipped=%d, undef_symbols=%d, tc_errors=%d, tc_warnings=%d)",
            result.skipped_hard_count,
            result.skipped_exact_count,
            result.undef_symbol_count,
            result.typecheck_error_count,
            result.typecheck_warning_count,
        )
    return result


# -----------------------------------------------------------------------
# Z3Encoder (incremental encode path: CEGAR)
# -----------------------------------------------------------------------


def _deref_base_symbol(expr: Expr) -> str | None:
    if expr.op in (ExprOp.SYMBOL, ExprOp.FRESH) and expr.symbol:
        return expr.symbol
    if expr.op == ExprOp.ADD and expr.args:
        return _deref_base_symbol(expr.args[0])
    return None


def _ensure_deref_bases_as_ptr(expr: Expr, symbol_table: SymbolTable) -> None:
    if expr.op == ExprOp.DEREF and expr.args:
        base = _deref_base_symbol(expr.args[0])
        if base and base not in symbol_table.symbols:
            symbol_table.add(Symbol(name=base, sort=ctypes.c_void_p, bitwidth=64))
    for arg in getattr(expr, "args", ()):
        _ensure_deref_bases_as_ptr(arg, symbol_table)


def _ensure_symbols_in_table(expr: Expr, symbol_table: SymbolTable) -> None:
    """Ensure every SYMBOL/FRESH in the expr tree is in the symbol table (for Z3Encoder's ad-hoc table)."""
    if (
        expr.op in (ExprOp.SYMBOL, ExprOp.FRESH)
        and expr.symbol
        and expr.symbol not in symbol_table.symbols
    ):
        symbol_table.add(
            Symbol(
                name=expr.symbol,
                sort=int,
                bitwidth=expr.bitwidth or 64,
            )
        )
    for arg in getattr(expr, "args", ()):
        _ensure_symbols_in_table(arg, symbol_table)


def _tracked_symbols_from_constraints(constraints: list[Constraint]) -> set[str]:
    out: set[str] = set()
    for c in constraints:
        if c.kind != ConstraintKind.ASSIGN or not c.expr.args:
            continue
        lhs = c.expr.args[0]
        if lhs.op in (ExprOp.SYMBOL, ExprOp.FRESH) and lhs.symbol:
            out.add(lhs.symbol)
    return out


def translate_to_z3(
    constraints: list[Constraint],
    symbol_table: SymbolTable,
) -> Z3TranslationResult:
    """IR -> Z3 translation: typecheck, var factory, translate, classify hard/soft, field-memory links."""
    tc = TypecheckPass(constraints, symbol_table)
    tc_diags, skip_ids = tc.run()

    tc_errors = sum(1 for d in tc_diags if d.level == DiagLevel.ERROR)
    tc_warnings = sum(1 for d in tc_diags if d.level == DiagLevel.WARNING)
    if tc_errors or skip_ids:
        logger.info(
            "[!] Typecheck: %d errors, %d warnings, %d skipped",
            tc_errors,
            tc_warnings,
            len(skip_ids),
        )
    constraint_by_id = {c.id: c for c in constraints}
    for d in tc_diags:
        if d.level == DiagLevel.ERROR:
            logger.error("  typecheck error in %s: %s", d.constraint_id, d.message)
          #  logger.info("expr.json=%s", json.dumps(constraint_by_id[d.constraint_id].expr.to_dict(), indent=2))

            while True:
                key = input("Press K to continue: ").strip().upper()
                if key == "K":
                    break

    vf = Z3VarFactory(symbol_table)
    tr = ExprTranslator(vf, symbol_table)

    hard: list[str] = []
    soft: list[str] = []
    soft_weights: dict[str, int] = {}
    skipped: list[tuple[str, str]] = []
    trans_diags: list[str] = []
    z3_exprs: dict[str, z3.ExprRef] = {}

    for c in constraints:
        if c.id in skip_ids:
            skipped.append((c.id, "typecheck error"))
            continue
        try:
            z3_expr = tr.translate(c.expr)
        except (TranslationError, KeyError, z3.Z3Exception) as e:
            skipped.append((c.id, str(e)))
            trans_diags.append(f"skip {c.id}: {e}")
            continue
        if z3.is_bv(z3_expr):
            z3_expr = z3_expr != z3.BitVecVal(0, z3_expr.size())
        z3_exprs[c.id] = z3_expr
        if c.soft or c.confidence < HARD_CONFIDENCE_THRESHOLD:
            soft.append(c.id)
            soft_weights[c.id] = compute_weight(c)
        else:
            hard.append(c.id)

    undef_skips = sum(
        1
        for _, reason in skipped
        if "Symbol not found" in reason or "undefined symbol" in reason
    )
    if undef_skips:
        logger.info("[!] %d constraints skipped due to undefined symbols", undef_skips)

    field_links = 0
    for fa in symbol_table.fields._accesses.values():
        field_name = fa.symbol.name
        latest_name = field_name
        for sym_name in symbol_table.symbols:
            if sym_name.startswith(field_name + "#"):
                try:
                    ver = int(sym_name.rsplit("#", 1)[1])
                    cur_ver = (
                        int(latest_name.rsplit("#", 1)[1]) if "#" in latest_name else -1
                    )
                    if ver > cur_ver:
                        latest_name = sym_name
                except (ValueError, IndexError):
                    pass
        cid = f"c_field_link_{latest_name}"
        if cid in z3_exprs:
            continue
        try:
            buf_short = fa.buffer_symbol.removesuffix("_base")
            mem8_func = vf.get_buffer_mem8(buf_short)
            base_var = vf.get_var(fa.buffer_symbol)
            n_bytes = fa.width
            bytes_exprs = [
                mem8_func(base_var + z3.BitVecVal(fa.offset + i, 64))
                for i in range(n_bytes)
            ]
            deref_val = (
                bytes_exprs[0]
                if len(bytes_exprs) == 1
                else z3.Concat(*reversed(bytes_exprs))
            )
            field_var = vf.get_var(latest_name)
            z3_exprs[cid] = field_var == deref_val
            hard.append(cid)
            field_links += 1
        except (KeyError, z3.Z3Exception) as e:
            trans_diags.append(f"field link skip {latest_name}: {e}")

    return Z3TranslationResult(
        z3_vars=vf.all_vars,
        z3_exprs=z3_exprs,
        hard_constraint_ids=hard,
        soft_constraint_ids=soft,
        soft_weights=soft_weights,
        skipped_constraints=skipped,
        typecheck_diagnostics=tc_diags,
        translation_diagnostics=trans_diags,
        deref_functions=vf.deref_functions,
    )


class Z3Encoder:
    """Encoder that uses translate_to_z3 for translation and field-memory linking."""

    def __init__(
        self,
        *,
        branch_forcers: list[tuple[int, bool]] | None = None,
    ) -> None:
        self._constraints: list[Constraint] = []
        self._z3_result: Z3TranslationResult | None = None
        self._solver: z3.Solver | None = None
        self._ite_conds: list[tuple[z3.BoolRef, int | None, int | None]] = []
        self._tracked_symbols: set[str] = set()
        self._branch_forcers: list[tuple[int, bool]] = list(branch_forcers or [])
        self._symbolic_offset_var: z3.ExprRef | None = None

    def add_constraint(self, constraint: Constraint) -> None:
        self._constraints.append(constraint)
        self._z3_result = None
        self._solver = None
        self._ite_conds = []

    def _ensure_translated(self) -> None:
        if self._z3_result is not None and self._solver is not None:
            return
        if not self._constraints:
            self._solver = z3.Solver()
            self._z3_result = Z3TranslationResult(
                z3_vars={},
                z3_exprs={},
                hard_constraint_ids=[],
                soft_constraint_ids=[],
            )
            return

        symbol_table = SymbolTable()
        for c in self._constraints:
            _ensure_deref_bases_as_ptr(c.expr, symbol_table)
            _ensure_symbols_in_table(c.expr, symbol_table)

        ir_constraints = [
            Constraint(
                id=f"c_{i}",
                expr=c.expr,
                parent_block_ea=str(c.parent_block_ea),
                kind=ConstraintKind.OPAQUE,
                soft=False,
                confidence=1.0,
            )
            for i, c in enumerate(self._constraints)
        ]

        self._z3_result = translate_to_z3(ir_constraints, symbol_table)
        self._tracked_symbols = _tracked_symbols_from_constraints(self._constraints)

        self._solver = z3.Solver()
        for cid in self._z3_result.hard_constraint_ids:
            if cid not in self._z3_result.z3_exprs:
                continue
            try:
                idx = int(cid.split("_", 1)[1])
            except (ValueError, IndexError):
                idx = -1
            # IT/ITE are branch structure only: do not assert their condition (would conflict with exception blocker cond=False).
            if 0 <= idx < len(self._constraints) and self._constraints[idx].kind in (
                ConstraintKind.IT,
                ConstraintKind.ITE,
                ConstraintKind.SWITCH,
                ConstraintKind.SWITCH_COND,
            ):
                logger.debug("skip IT/ITE %s for solver (branch structure only)", cid)
                continue
            z3_expr = self._z3_result.z3_exprs[cid]
            track = z3.Bool(cid)
            self._solver.assert_and_track(z3_expr, track)

        self._ite_conds = []
        for i, c in enumerate(self._constraints):
            if c.kind not in (ConstraintKind.IT, ConstraintKind.ITE, ConstraintKind.SWITCH_COND):
                continue
            cid = f"c_{i}"
            cond_z3 = self._z3_result.z3_exprs.get(cid)
            if cond_z3 is not None and z3.is_bool(cond_z3):
                else_ea = (
                    c.else_block_ea if c.kind == ConstraintKind.ITE else c.fallthru_ea
                )
                self._ite_conds.append((cond_z3, c.then_block_ea, else_ea))
        for i, val in self._branch_forcers:
            if 0 <= i < len(self._ite_conds):
                self._solver.add(self._ite_conds[i][0] == val)

    def encode_expr(self, expr: Expr) -> z3.ExprRef:
        self._ensure_translated()
        raise NotImplementedError(
            "encode_expr not available when using translate_to_z3 batch translation"
        )

    def check(self) -> z3.CheckSatResult:
        self._ensure_translated()
        assert self._solver is not None
        return self._solver.check()

    def check_with_extra(self, extra: z3.BoolRef) -> z3.CheckSatResult:
        """Check satisfiability with one temporary assertion (push/add/check/pop)."""
        self._ensure_translated()
        assert self._solver is not None
        self._solver.push()
        self._solver.add(extra)
        result = self._solver.check()
        self._solver.pop()
        return result

    def check_any_path(self) -> z3.CheckSatResult:
        self._ensure_translated()
        assert self._solver is not None
        self._solver.set("timeout", 10_000)  # 10s per model

        return self._solver.check()

    def get_ite_conds(self) -> list[tuple[z3.BoolRef, int | None, int | None]]:
        self._ensure_translated()
        return list(self._ite_conds)

    def get_unsat_core(self) -> list[str]:
        """Return constraint ids in the unsat core. Only valid after check()/check_any_path() returned unsat."""
        self._ensure_translated()
        assert self._solver is not None
        core = self._solver.unsat_core()
        return [x.decl().name() for x in core]

    def decode_path_from_model(self) -> tuple[bool, ...]:
        self._ensure_translated()
        assert self._solver is not None
        model = self._solver.model()
        result: list[bool] = []
        for cond, _then_ea, _else_ea in self._ite_conds:
            result.append(bool(model.eval(cond, model_completion=True)))
        return tuple(result)

    def add_path_blocker(self, path_choices: tuple[bool, ...]) -> None:
        self._ensure_translated()
        logger.info("add_path_blocker path_choices=%s", path_choices)
        assert self._solver is not None
        if len(path_choices) != len(self._ite_conds):
            return
        terms = []
        for i, (cond, _then_ea, _else_ea) in enumerate(self._ite_conds):
            terms.append(cond if path_choices[i] else z3.Not(cond))
        self._solver.add(z3.Not(z3.And(*terms)))

    def get_z3_var(self, name: str) -> z3.ExprRef | None:
        """Return the Z3 expression for a symbol name, if present. Used for hypothesis (e.g. sink == input_val)."""
        self._ensure_translated()
        if self._z3_result is None:
            return None
        return self._z3_result.z3_vars.get(name)

    def add_symbolic_input_hypothesis(
        self,
        sink_var_name: str,
        num_bytes: int = 8,
    ) -> bool:
        """Add symbolic input buffer and hypothesis (sink == input_val at symbolic offset).
        Model input as array buf[index]->byte, symbolic offset; add constraint that the
        sink value equals the value read at that offset. After check()==sat, get_model()
        will include 'offset' (and optionally decoded bytes). Returns True if sink var
        was found and constraints were added."""
        self._ensure_translated()
        assert self._solver is not None
        sink_z3 = self.get_z3_var(sink_var_name)
        if sink_z3 is None:
            return False
        # Symbolic buffer: index -> 8-bit byte
        buf = z3.Array("buf", z3.BitVecSort(64), z3.BitVecSort(8))
        offset = z3.BitVec("offset", 64)
        self._symbolic_offset_var = offset
        # Read num_bytes at symbolic offset (little-endian)
        bytes_at_offset = [z3.Select(buf, offset + i) for i in range(num_bytes)]
        input_val = z3.Concat(list(reversed(bytes_at_offset)))
        # Match bit width: sink may be 32- or 64-bit
        sink_bw = sink_z3.size() if hasattr(sink_z3, "size") else 64
        input_bw = input_val.size()
        if sink_bw < input_bw:
            input_val = z3.Extract(sink_bw - 1, 0, input_val)
        elif sink_bw > input_bw:
            input_val = z3.ZeroExt(sink_bw - input_bw, input_val)
        self._solver.add(sink_z3 == input_val)
        return True

    def get_model(self) -> dict[str, int]:
        self._ensure_translated()
        assert self._solver is not None and self._z3_result is not None
        model = self._solver.model()
        result: dict[str, int] = {}
        for name, z3_var in self._z3_result.z3_vars.items():
            if name not in self._tracked_symbols and not name.startswith("_fresh_"):
                continue
            value = model.eval(z3_var, model_completion=True)
            result[name] = value.as_long() if hasattr(value, "as_long") else 0
        if self._symbolic_offset_var is not None:
            try:
                val = model.eval(self._symbolic_offset_var, model_completion=True)
                result["offset"] = val.as_long() if hasattr(val, "as_long") else 0
            except Exception:
                pass
        return result

    def sexpr(self) -> str:
        self._ensure_translated()
        assert self._solver is not None
        return self._solver.sexpr()

    def push(self) -> None:
        self._ensure_translated()
        assert self._solver is not None
        self._solver.push()

    def pop(self) -> None:
        self._ensure_translated()
        assert self._solver is not None
        self._solver.pop()
