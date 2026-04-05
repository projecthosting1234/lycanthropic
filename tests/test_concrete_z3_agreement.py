"""Agreement tests: concrete_eval vs Z3 for the same expressions."""

import pytest
import z3

from analysis.ir_schema import BVSort, Constraint, Expr, ExprOp, Symbol
from analysis.ir_to_z3.symbols import SymbolTable
from analysis.concrete_eval import eval_expr
from analysis.ir_to_z3.z3_translator import ExprTranslator, Z3VarFactory


def _make_st(*names):
    """Build a SymbolTable with 32-bit BV symbols."""
    st = SymbolTable()
    for n in names:
        st.add(Symbol(name=n, sort=BVSort(32), bitwidth=32, domain='test', origin='test'))
    return st


def _check_agreement(expr, concrete, st):
    """Assert concrete_eval and Z3 agree on the expression under the concrete map.

    For BV-valued expressions, wraps in ne(expr, 0) to get a boolean result
    before comparing.
    """
    # 1. Concrete eval
    c_result = eval_expr(expr, concrete, st)

    # 2. Z3 eval
    vf = Z3VarFactory(st)
    tr = ExprTranslator(vf, st)
    z3_expr = tr.translate(expr)

    solver = z3.Solver()
    # Fix all variables to their concrete values
    for name, val in concrete.items():
        try:
            z3_var = vf.get_var(name)
            if isinstance(val, bool):
                solver.add(z3_var == z3.BoolVal(val))
            elif z3.is_bv(z3_var):
                solver.add(z3_var == z3.BitVecVal(val, z3_var.size()))
        except KeyError:
            pass

    # Evaluate the expression under the concrete model
    if z3.is_bool(z3_expr):
        # Boolean expression: check if true or false
        sat_true = solver.check(z3_expr) == z3.sat
        sat_false = solver.check(z3.Not(z3_expr)) == z3.sat

        if c_result is True or (isinstance(c_result, tuple) and c_result[0] != 0):
            assert sat_true, "concrete says True but Z3 says UNSAT"
        elif c_result is False or (isinstance(c_result, tuple) and c_result[0] == 0):
            assert sat_false, "concrete says False but Z3 says UNSAT for negation"
        # c_result is None → unevaluable, skip
    elif z3.is_bv(z3_expr):
        # BV expression: evaluate to get the value
        if solver.check() == z3.sat:
            model = solver.model()
            z3_val = model.eval(z3_expr, model_completion=True)
            if c_result is not None and not isinstance(c_result, bool):
                c_val, c_bw = c_result
                assert z3.is_bv_value(z3_val), "Z3 should produce a BV value"
                assert z3_val.as_long() == c_val, \
                    "BV mismatch: concrete=%d, Z3=%d" % (c_val, z3_val.as_long())


# ── Arithmetic ────────────────────────────────────────────────────

def test_bvadd_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.BVADD, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(op=ExprOp.SYMBOL, symbol="y")])
    _check_agreement(expr, {"x": 100, "y": 200}, st)


def test_bvsub_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.BVSUB, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(op=ExprOp.SYMBOL, symbol="y")])
    _check_agreement(expr, {"x": 500, "y": 200}, st)


def test_bvsub_underflow_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.BVSUB, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(op=ExprOp.SYMBOL, symbol="y")])
    _check_agreement(expr, {"x": 0, "y": 1}, st)  # wraps to 0xFFFFFFFF


def test_bvmul_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVMUL, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=7, bitwidth=32)])
    _check_agreement(expr, {"x": 42}, st)


def test_bvudiv_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVUDIV, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=3, bitwidth=32)])
    _check_agreement(expr, {"x": 100}, st)


def test_bvsdiv_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVSDIV, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=3, bitwidth=32)])
    # x = -6 as 32-bit unsigned = 0xFFFFFFFA
    _check_agreement(expr, {"x": 0xFFFFFFFA}, st)


# ── Bitwise ───────────────────────────────────────────────────────

def test_bvand_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVAND, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0xFF, bitwidth=32)])
    _check_agreement(expr, {"x": 0xDEADBEEF}, st)


def test_bvor_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVOR, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0xF0, bitwidth=32)])
    _check_agreement(expr, {"x": 0x0A}, st)


def test_bvxor_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.BVXOR, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(op=ExprOp.SYMBOL, symbol="y")])
    _check_agreement(expr, {"x": 0xAAAA, "y": 0x5555}, st)


def test_bvshl_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVSHL, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=4, bitwidth=32)])
    _check_agreement(expr, {"x": 0x1234}, st)


def test_bvlshr_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVLSHR, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=8, bitwidth=32)])
    _check_agreement(expr, {"x": 0xABCD0000}, st)


# ── Comparisons ───────────────────────────────────────────────────

def test_eq_true_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=42, bitwidth=32)])
    _check_agreement(expr, {"x": 42}, st)


def test_eq_false_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=42, bitwidth=32)])
    _check_agreement(expr, {"x": 99}, st)


def test_ne_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.NE, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0, bitwidth=32)])
    _check_agreement(expr, {"x": 1}, st)


def test_bvult_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVULT, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=100, bitwidth=32)])
    _check_agreement(expr, {"x": 50}, st)
    _check_agreement(expr, {"x": 200}, st)


def test_bvuge_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVUGE, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=10, bitwidth=32)])
    _check_agreement(expr, {"x": 10}, st)
    _check_agreement(expr, {"x": 5}, st)


def test_bvslt_signed_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.BVSLT, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0, bitwidth=32)])
    # x = -1 as unsigned 32-bit = 0xFFFFFFFF
    _check_agreement(expr, {"x": 0xFFFFFFFF}, st)
    _check_agreement(expr, {"x": 1}, st)


# ── Width ops ─────────────────────────────────────────────────────

def test_extract_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.EXTRACT, args=[Expr(op=ExprOp.SYMBOL, symbol="x")],
                extract_hi=15, extract_lo=8, bitwidth=8)
    _check_agreement(expr, {"x": 0xDEADBEEF}, st)


def test_concat_agreement():
    st = SymbolTable()
    st.add(Symbol(name='a', sort=int, bitwidth=16, domain='test', origin='test'))
    st.add(Symbol(name='b', sort=int, bitwidth=16, domain='test', origin='test'))
    expr = Expr(op=ExprOp.CONCAT, args=[Expr(op=ExprOp.SYMBOL, symbol="a"), Expr(op=ExprOp.SYMBOL, symbol="b")])
    _check_agreement(expr, {"a": 0xABCD, "b": 0x1234}, st)


def test_zext_agreement():
    st = SymbolTable()
    st.add(Symbol(name='x', sort=int, bitwidth=16, domain='test', origin='test'))
    expr = Expr(op=ExprOp.ZEXT, args=[Expr(op=ExprOp.SYMBOL, symbol="x")], bitwidth=32)
    _check_agreement(expr, {"x": 0xFFFF}, st)


def test_sext_agreement():
    st = SymbolTable()
    st.add(Symbol(name='x', sort=int, bitwidth=16, domain='test', origin='test'))
    expr = Expr(op=ExprOp.SEXT, args=[Expr(op=ExprOp.SYMBOL, symbol="x")], bitwidth=32)
    # x = -1 as unsigned 16-bit = 0xFFFF → sext to 32-bit = 0xFFFFFFFF
    _check_agreement(expr, {"x": 0xFFFF}, st)


# ── Boolean ops ───────────────────────────────────────────────────

def test_and_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.AND, args=[
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=10, bitwidth=32)]),
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="y"), Expr(literal=20, bitwidth=32)]),
    ])
    _check_agreement(expr, {"x": 10, "y": 20}, st)
    _check_agreement(expr, {"x": 10, "y": 99}, st)


def test_or_agreement():
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.OR, args=[
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=10, bitwidth=32)]),
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="y"), Expr(literal=20, bitwidth=32)]),
    ])
    _check_agreement(expr, {"x": 99, "y": 20}, st)
    _check_agreement(expr, {"x": 99, "y": 99}, st)


def test_not_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.NOT, args=[
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0, bitwidth=32)]),
    ])
    _check_agreement(expr, {"x": 0}, st)
    _check_agreement(expr, {"x": 1}, st)


# ── ITE ───────────────────────────────────────────────────────────

def test_ite_agreement():
    st = _make_st("x")
    expr = Expr(op=ExprOp.ITE, args=[
        Expr(op=ExprOp.EQ, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=1, bitwidth=32)]),
        Expr(literal=100, bitwidth=32),   # then
        Expr(literal=200, bitwidth=32),   # else
    ])
    _check_agreement(expr, {"x": 1}, st)
    _check_agreement(expr, {"x": 0}, st)


# ── Compound nested ──────────────────────────────────────────────

def test_nested_compound_agreement():
    """bvult(bvadd(x, y), 1000) AND ne(bvand(x, 0xFF), 0)"""
    st = _make_st("x", "y")
    expr = Expr(op=ExprOp.AND, args=[
        Expr(op=ExprOp.BVULT, args=[
            Expr(op=ExprOp.BVADD, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(op=ExprOp.SYMBOL, symbol="y")]),
            Expr(literal=1000, bitwidth=32),
        ]),
        Expr(op=ExprOp.NE, args=[
            Expr(op=ExprOp.BVAND, args=[Expr(op=ExprOp.SYMBOL, symbol="x"), Expr(literal=0xFF, bitwidth=32)]),
            Expr(literal=0, bitwidth=32),
        ]),
    ])
    _check_agreement(expr, {"x": 50, "y": 100}, st)
    _check_agreement(expr, {"x": 500, "y": 600}, st)
