from __future__ import annotations

from typing import Any, Tuple

from analysis.ir_to_z3.symbols import SymbolTable


def eval_expr(expr: Any, concrete: dict[str, int], symbol_table: SymbolTable):
    """Evaluate an Expr under a concrete variable assignment with given symbol table."""

    if expr.literal is not None:
        if isinstance(expr.literal, bool):
            return expr.literal
        return expr.literal, expr.bitwidth or 64

    if expr.symbol:
        value = concrete.get(expr.symbol, 0)
        bw = _get_bitwidth(expr.symbol, symbol_table)
        return value & _mask_for(bw), bw

    if not expr.op:
        return 0, 64

    op = _op_name(expr)
    args = [eval_expr(arg, concrete, symbol_table) for arg in expr.args]

    if op in {"bvadd", "bvsub", "bvmul", "bvudiv", "bvsdiv", "bvand", "bvor", "bvxor", "bvshl", "bvlshr", "bvashr"}:
        return _eval_bv_op(op, expr, args)

    if op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
        return _eval_cmp(op, args)

    if op in {"and", "or"}:
        return _to_bool(args[0]) and _to_bool(args[1]) if op == "and" else _to_bool(args[0]) or _to_bool(args[1])

    if op == "not":
        return not _to_bool(args[0])

    if op == "ite":
        cond = _to_bool(args[0])
        branch = args[1] if cond else args[2]
        return branch

    if op == "extract":
        value, _ = args[0]
        hi, lo = expr.extract_hi or 0, expr.extract_lo or 0
        width = hi - lo + 1
        mask = (1 << width) - 1
        return (value >> lo) & mask, width

    if op == "concat":
        total = 0
        width = 0
        for val, bw in args:
            total = (total << bw) | (val & _mask_for(bw))
            width += bw
        return total, width

    if op == "zext":
        value, bw = args[0]
        target = expr.bitwidth or bw
        return value & _mask_for(bw), target

    if op == "sext":
        value, bw = args[0]
        target = expr.bitwidth or bw
        signed = _to_signed(value, bw)
        mask = _mask_for(target)
        return signed & mask, target

    return _to_bool(args[0])


def _op_name(expr: Any) -> str:
    op = expr.op
    if hasattr(op, "value"):
        return str(op.value)
    return str(expr.op or "")


def _mask_for(bitwidth: int) -> int:
    if bitwidth >= 128:
        return (1 << 128) - 1
    return (1 << bitwidth) - 1


def _to_bool(arg) -> bool:
    if isinstance(arg, bool):
        return arg
    if isinstance(arg, tuple):
        return arg[0] != 0
    return bool(arg)


def _to_signed(value: int, bitwidth: int) -> int:
    if value & (1 << (bitwidth - 1)):
        return value - (1 << bitwidth)
    return value


def _get_bitwidth(name: str, symbol_table: SymbolTable) -> int:
    expr = symbol_table.get(name)
    if expr and expr.bitwidth:
        return expr.bitwidth
    return 64


def _eval_bv_op(op: str, expr: Any, args: list[Tuple[int, int]]):
    left, left_bw = args[0]
    right, right_bw = args[1]
    target_bw = expr.bitwidth or max(left_bw, right_bw)
    mask = _mask_for(target_bw)

    if op in {"bvadd", "bvmul"}:
        result = left + right if op == "bvadd" else left * right
    elif op == "bvsub":
        result = left - right
    elif op == "bvudiv":
        result = left // right if right else 0
    elif op == "bvsdiv":
        result = _to_signed(left, left_bw)
        denominator = _to_signed(right, right_bw)
        result = result // denominator if denominator else 0
    elif op == "bvand":
        result = left & right
    elif op == "bvor":
        result = left | right
    elif op == "bvxor":
        result = left ^ right
    elif op == "bvshl":
        result = left << right
    elif op == "bvlshr":
        result = (left & _mask_for(left_bw)) >> right
    elif op == "bvashr":
        result = _to_signed(left, left_bw) >> right
    else:
        result = left

    return result & mask, target_bw


def _eval_cmp(op: str, args: list[Tuple[int, int]]):
    left, left_bw = args[0]
    right, right_bw = args[1]
    if op in {"eq", "ne"}:
        cmp_result = (left == right)
        return not cmp_result if op == "ne" else cmp_result
    if op.startswith("bv"):
        return _to_unsigned(left, left_bw, op, right, right_bw)
    signed_left = _to_signed(left, left_bw)
    signed_right = _to_signed(right, right_bw)
    if op == "slt":
        return signed_left < signed_right
    if op == "sle":
        return signed_left <= signed_right
    if op == "sgt":
        return signed_left > signed_right
    if op == "sge":
        return signed_left >= signed_right
    return False


def _to_unsigned(left, left_bw, op, right, right_bw):
    if op == "ult":
        return left < right
    if op == "ule":
        return left <= right
    if op == "ugt":
        return left > right
    if op == "uge":
        return left >= right
    return False
