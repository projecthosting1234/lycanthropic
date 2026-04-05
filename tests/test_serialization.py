"""Serialization round-trip tests for Constraint IR."""

import pytest
from dataclasses import asdict

from analysis.ir_schema import (
    Assumption, Constraint, ConstraintKind, Expr, ExprOp,
    FactClass, Symbol, ir_to_dict,
)
from analysis.ir_to_z3.symbols import (
    BufferMethod, DriverModel, SymbolTable,
)


# ── Expr round-trips ──────────────────────────────────────────────

def test_expr_literal_int_roundtrip():
    orig = Expr(literal=42, bitwidth=32)
    d = asdict(orig)
    rebuilt = Expr.from_dict(d)
    assert rebuilt.literal == 42
    assert rebuilt.bitwidth == 32
    assert rebuilt.op is None
    assert rebuilt.symbol is None


def test_expr_literal_bool_roundtrip():
    for val in (True, False):
        orig = Expr(literal=val)
        rebuilt = Expr.from_dict(asdict(orig))
        assert rebuilt.literal is val


def test_expr_symbol_roundtrip():
    orig = Expr(op=ExprOp.SYMBOL, symbol="ioctl_code")
    rebuilt = Expr.from_dict(asdict(orig))
    assert rebuilt.symbol == "ioctl_code"


def test_expr_compound_bvadd_roundtrip():
    orig = Expr(op=ExprOp.BVADD, args=[
        Expr(op=ExprOp.SYMBOL, symbol="x"),
        Expr(literal=0x10, bitwidth=32),
    ])
    rebuilt = Expr.from_dict(asdict(orig))
    assert rebuilt.op == "bvadd"
    assert len(rebuilt.args) == 2
    assert rebuilt.args[0].symbol == "x"
    assert rebuilt.args[1].literal == 0x10
    assert rebuilt.args[1].bitwidth == 32


def test_expr_extract_roundtrip():
    orig = Expr(op=ExprOp.EXTRACT, args=[Expr(op=ExprOp.SYMBOL, symbol="x")],
                extract_hi=31, extract_lo=16, bitwidth=16)
    rebuilt = Expr.from_dict(asdict(orig))
    assert rebuilt.extract_hi == 31
    assert rebuilt.extract_lo == 16
    assert rebuilt.bitwidth == 16
    assert rebuilt.args[0].symbol == "x"


def test_expr_nested_roundtrip():
    """Deeply nested: and(eq(x, 10), not(bvult(y, 5)))"""
    orig = Expr(op=ExprOp.AND, args=[
        Expr(op=ExprOp.EQ, args=[
            Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=10, bitwidth=32),
        ]),
        Expr(op=ExprOp.NOT, args=[
            Expr(op=ExprOp.BVULT, args=[
                Expr(op=ExprOp.SYMBOL, symbol="y"), Expr(literal=5, bitwidth=32),
            ]),
        ]),
    ])
    rebuilt = Expr.from_dict(asdict(orig))
    assert rebuilt.op == "and"
    assert len(rebuilt.args) == 2
    assert rebuilt.args[0].op == "eq"
    assert rebuilt.args[1].op == "not"
    assert rebuilt.args[1].args[0].op == "bvult"
    assert rebuilt.args[1].args[0].args[1].literal == 5


def test_expr_all_leaf_types():
    """Each leaf type round-trips correctly."""
    for expr in [
        Expr(literal=0, bitwidth=64),
        Expr(literal=True),
        Expr(literal=False),
        Expr(op=ExprOp.SYMBOL, symbol="some_var@0x1234"),
    ]:
        rebuilt = Expr.from_dict(asdict(expr))
        assert rebuilt.literal == expr.literal
        assert rebuilt.symbol == expr.symbol
        assert rebuilt.bitwidth == expr.bitwidth


# ── Constraint round-trips ────────────────────────────────────────

def test_constraint_full_roundtrip():
    orig = Constraint(
        id="c_test_0",
        expr=Expr(op=ExprOp.NE, args=[
            Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0, bitwidth=32),
        ]),
        parent_block_ea="0x1234",
        kind=ConstraintKind.BRANCH_TAKEN,
        soft=True,
        model_tier=1,
        confidence=0.85,
        comment="test constraint",
        evidence_span="if (x != 0)",
        source_line=42,
        fact_class=FactClass.LLM_HYPOTHESIS,
    )
    d = ir_to_dict(orig)
    rebuilt = Constraint.from_dict(d)
    assert rebuilt.id == "c_test_0"
    assert rebuilt.parent_block_ea == "0x1234"
    assert rebuilt.kind == "branch_taken"
    assert rebuilt.soft is True
    assert rebuilt.model_tier == 1
    assert rebuilt.confidence == 0.85
    assert rebuilt.comment == "test constraint"
    assert rebuilt.evidence_span == "if (x != 0)"
    assert rebuilt.source_line == 42
    assert rebuilt.fact_class == "llm_hypothesis"
    assert rebuilt.expr.op == "ne"


def test_assumption_roundtrip():
    orig = Assumption(
        id="c_assume_0",
        expr=Expr(literal=True),
        node_ea="root",
        kind="environment",
    )
    d = ir_to_dict(orig)
    assert d["_type"] == "Assumption"
    rebuilt = Constraint.from_dict(d)
    assert isinstance(rebuilt, Assumption)
    assert rebuilt.id == "c_assume_0"


def test_constraint_missing_fields_compat():
    """Old-format dict without fact_class, signed, source_line → defaults."""
    d = {
        "id": "c_old_0",
        "expr": {"op": "eq", "args": [
            {"symbol": "x"}, {"literal": 5, "bitwidth": 32},
        ]},
        "node_ea": "0x1000",
        "kind": "branch_taken",
    }
    c = Constraint.from_dict(d)
    assert c.id == "c_old_0"
    assert c.fact_class == ""
    assert c.source_line is None
    assert c.soft is False
    assert c.confidence == 1.0


# ── Symbol round-trips ────────────────────────────────────────────

def test_symbol_int_sort_roundtrip():
    orig = Symbol(name="x", sort=int, bitwidth=32, domain="test", origin="test", signed=False)
    d = ir_to_dict(orig)
    rebuilt = Symbol.from_dict(d)
    assert rebuilt.name == "x"
    assert rebuilt.bitwidth == 32
    assert rebuilt.domain == "test"
    assert rebuilt.signed is False
    assert rebuilt.sort is int


def test_symbol_pointer_domain_roundtrip():
    orig = Symbol(name="inbuf_base", sort=int, bitwidth=64, domain="pointer", origin="root")
    d = ir_to_dict(orig)
    rebuilt = Symbol.from_dict(d)
    assert rebuilt.name == "inbuf_base"
    assert rebuilt.bitwidth == 64
    assert rebuilt.domain == "pointer"
    assert rebuilt.sort is int


# ── SymbolTable round-trips ───────────────────────────────────────

def test_symbol_table_roundtrip(simple_symbol_table):
    st = simple_symbol_table
    st.driver_model = DriverModel.WDM
    st.buffer_methods = [BufferMethod.SYSTEM_BUFFER]
    st.add_alias("outbuf_base", "inbuf_base")
    st.structural_constraints.append(Constraint(
        id="c_struct_0", expr=Expr(literal=True), parent_block_ea="domain", kind="domain",
    ))

    d = st.to_dict()
    rebuilt = SymbolTable.from_dict(d)

    assert rebuilt.driver_model == DriverModel.WDM
    assert BufferMethod.SYSTEM_BUFFER in rebuilt.buffer_methods
    assert any(s.name == "ioctl_code" for s in rebuilt.symbols)
    assert any(s.name == "x" for s in rebuilt.symbols)
    assert any(s.name == "inbuf_base" for s in rebuilt.symbols)
    # Alias preserved
    assert rebuilt.aliases.find("outbuf_base") == "inbuf_base"
    # Structural constraint preserved
    assert len(rebuilt.structural_constraints) >= 1
    assert rebuilt.structural_constraints[0].id == "c_struct_0"
