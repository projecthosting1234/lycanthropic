"""Tests for IR helpers: weights, classification, snapshot, normalization, integrity."""

import pytest

from analysis.ir_schema import (
    Assumption, BVSort, Constraint, ConstraintKind, Expr, ExprOp,
    FactClass, PtrSort, SolveQuality, Symbol,
    EXACT_FACT_CLASSES, apply_required_normalization, canonicalize_commutative_args,
    classify_solve_quality, is_exact,
)
from analysis.ir_to_z3.z3_translator import (
    IntegrityResult, compute_weight, validate_translation_integrity,
    HARD_CONFIDENCE_THRESHOLD, Z3TranslationResult, DiagLevel, TypecheckDiagnostic,
)
from analysis.ir_to_z3.symbols import SymbolTable


def _c(fact_class="", confidence=1.0, model_tier=0, soft=False, cid="c_test", kind="branch_taken"):
    return Constraint(
        id=cid, expr=Expr(literal=True), parent_block_ea="0x1000",
        kind=kind, confidence=confidence, model_tier=model_tier,
        soft=soft, fact_class=fact_class,
    )


# ── compute_weight ────────────────────────────────────────────────

class TestComputeWeight:
    def test_exact_mined_full(self):
        assert compute_weight(_c("exact_mined", 1.0, 0)) == 100

    def test_ctree_fact_full(self):
        assert compute_weight(_c("ctree_fact", 1.0, 0)) == 100

    def test_llm_hypothesis(self):
        assert compute_weight(_c("llm_hypothesis", 0.95, 0)) == 38

    def test_ssa_structural(self):
        assert compute_weight(_c("ssa_structural", 0.95, 0)) == 76

    def test_mined_heuristic_tier1(self):
        assert compute_weight(_c("exact_mined", 0.9, 1)) == 63

    def test_concrete_weakened_low(self):
        assert compute_weight(_c("concrete_weakened", 0.3, 0)) == 3

    def test_zero_confidence(self):
        assert compute_weight(_c("exact_mined", 0.0, 0)) == 1  # min clamp

    def test_unknown_fact_class(self):
        assert compute_weight(_c("unknown_class", 0.5, 0)) == 15  # default 30 * 1.0 * 0.5

    def test_unknown_tier(self):
        assert compute_weight(_c("exact_mined", 1.0, 99)) == 50  # 100 * 0.5 * 1.0

    def test_enum_fact_class(self):
        """FactClass enum value works correctly (Python 3.8 compat)."""
        c = _c(FactClass.EXACT_MINED, 1.0, 0)
        assert compute_weight(c) == 100


# ── is_exact ──────────────────────────────────────────────────────

class TestIsExact:
    @pytest.mark.parametrize("fc", ["exact_mined", "ctree_fact", "ssa_structural", "environment"])
    def test_exact_strings(self, fc):
        assert is_exact(_c(fc)) is True

    @pytest.mark.parametrize("fc", [
        FactClass.EXACT_MINED, FactClass.CTREE_FACT,
        FactClass.SSA_STRUCTURAL, FactClass.ENVIRONMENT,
    ])
    def test_exact_enums(self, fc):
        assert is_exact(_c(fc)) is True

    @pytest.mark.parametrize("fc", ["llm_hypothesis", "concrete_weakened", "", "field_structural"])
    def test_heuristic_strings(self, fc):
        assert is_exact(_c(fc)) is False

    @pytest.mark.parametrize("fc", [FactClass.LLM_HYPOTHESIS, FactClass.CONCRETE_WEAKENED])
    def test_heuristic_enums(self, fc):
        assert is_exact(_c(fc)) is False


# ── classify_solve_quality ────────────────────────────────────────

class TestClassifySolveQuality:
    def test_sat_exact(self):
        assert classify_solve_quality("sat", [], [], []) == SolveQuality.SAT_EXACT

    def test_sat_conservative(self):
        assert classify_solve_quality("sat", ["c_soft_0"], [], []) == SolveQuality.SAT_CONSERVATIVE

    def test_unsat_plain(self):
        c = _c("llm_hypothesis", cid="c_llm_0")
        assert classify_solve_quality("unsat", [], ["c_llm_0"], [c]) == SolveQuality.UNSAT

    def test_inconsistent_input(self):
        c = _c("exact_mined", cid="c_mined_0")
        assert classify_solve_quality("unsat", [], ["c_mined_0"], [c]) == SolveQuality.INCONSISTENT_INPUT

    def test_inconsistent_ctree(self):
        c = _c("ctree_fact", cid="c_ctree_0")
        assert classify_solve_quality("unsat", [], ["c_ctree_0"], [c]) == SolveQuality.INCONSISTENT_INPUT

    def test_unsat_degraded_exact(self):
        c = _c("exact_mined", model_tier=1, cid="c_mined_0")
        assert classify_solve_quality("unsat", [], ["c_mined_0"], [c]) == SolveQuality.UNSAT

    def test_unknown(self):
        assert classify_solve_quality("unknown", [], [], []) == SolveQuality.UNKNOWN_INCOMPLETE

    def test_error(self):
        assert classify_solve_quality("error", [], [], []) == SolveQuality.ERROR

    def test_empty_core(self):
        assert classify_solve_quality("unsat", [], [], []) == SolveQuality.UNSAT

    def test_missing_core_id(self):
        assert classify_solve_quality("unsat", [], ["c_missing"], []) == SolveQuality.UNSAT


# ── Snapshot ──────────────────────────────────────────────────────

class TestSnapshot:
    def test_copy_expr_deep_independence(self):
        orig = Expr(op=ExprOp.BVADD, args=(
            Expr(op=ExprOp.SYMBOL, symbol="x"),
            Expr(op=ExprOp.LITERAL, literal=10, bitwidth=32),
        ))
        copy = Expr.copy(orig)
        # Expr is frozen; verify copy is a deep copy (new objects, same structure)
        assert copy is not orig
        assert copy.args[0] is not orig.args[0]
        assert copy.args[1] is not orig.args[1]
        assert copy == orig
        assert orig.args[1].literal == 10

    def test_copy_constraint_preserves_assumption(self):
        orig = Assumption(id="a", expr=Expr(literal=True), node_ea="root", kind="environment")
        copy = copy_constraint(orig)
        assert isinstance(copy, Assumption)
        assert copy is not orig

    def test_snapshot_constraints_isolation(self):
        originals = [_c(cid="c_0"), _c(cid="c_1")]
        snap = Constraint.snapshot_list(originals)
        snap.append(_c(cid="c_2"))
        assert len(originals) == 2
        snap[0].soft = True
        assert originals[0].soft is False


# ── Normalization ─────────────────────────────────────────────────

class TestNormalization:
    def _make_st(self):
        st = SymbolTable()
        st.add(Symbol(name='x', sort=BVSort(32), bitwidth=32, domain='test', origin='test'))
        st.add(Symbol(name='y', sort=BVSort(32), bitwidth=32, domain='test', origin='test'))
        return st

    def test_literal_bitwidth_inference(self):
        st = self._make_st()
        c = Constraint(
            id="c_test", parent_block_ea="0x1000", kind="branch_taken",
            expr=Expr(op=ExprOp.EQ, args=[
                Expr(op=ExprOp.SYMBOL, symbol="x"),
                Expr(literal=42),  # missing bitwidth
            ]),
        )
        apply_required_normalization([c])
        # After normalization (rule 1), literal should have inferred bitwidth
        # The expr is now ne(eq(x, 42), 0) due to top-level BV wrapping... no.
        # Actually eq produces bool, so top-level wrapping doesn't apply.
        # The literal should have bitwidth=32 inferred from sibling x.
        inner = c.expr  # might be wrapped in NOT if it was treated as BV
        # Find the literal in the tree
        def find_literal(e):
            if e.literal is not None and not isinstance(e.literal, bool):
                return e
            for a in e.args:
                r = find_literal(a)
                if r is not None:
                    return r
            return None
        lit = find_literal(c.expr)
        assert lit is not None
        assert lit.bitwidth == 32

    def test_top_level_bv_wrapped(self):
        """Rule 4: top-level BV expr is wrapped in ne(expr, 0)."""
        c = Constraint(
            id="c_test", parent_block_ea="0x1000", kind="branch_taken",
            expr=Expr(op=ExprOp.BVADD, args=[
                Expr(op=ExprOp.SYMBOL, symbol="x"),
                Expr(literal=1, bitwidth=32),
            ], bitwidth=32),
        )
        apply_required_normalization([c])
        assert c.expr.op == ExprOp.NE
        assert len(c.expr.args) == 2
        assert c.expr.args[0].op == ExprOp.BVADD
        assert c.expr.args[1].op == ExprOp.LITERAL and c.expr.args[1].literal == 0

    def test_commutative_args_canonicalized(self):
        """Rule 9: commutative op args are sorted for deterministic order."""
        # bvadd(lit, sym) -> canonical order sym then lit
        e = Expr(op=ExprOp.BVADD, args=[
            Expr(literal=1, bitwidth=32),
            Expr(op=ExprOp.SYMBOL, symbol="x"),
        ], bitwidth=32)
        out = canonicalize_commutative_args(e)
        assert out.args[0].symbol == "x"
        assert out.args[1].literal == 1


# ── Integrity ─────────────────────────────────────────────────────

class TestIntegrity:
    def _z3r(self, skipped=None, tc_diags=None):
        return Z3TranslationResult(
            z3_vars={}, z3_exprs={},
            hard_constraint_ids=[], soft_constraint_ids=[],
            skipped_constraints=skipped or [],
            typecheck_diagnostics=tc_diags or [],
        )

    def test_no_skips_passes(self):
        r = validate_translation_integrity(self._z3r(), [_c(cid="c_0")])
        assert r.passed is True
        assert r.skipped_hard_count == 0

    def test_skipped_hard_fails(self):
        r = validate_translation_integrity(
            self._z3r(skipped=[("c_0", "typecheck error")]),
            [_c("llm_hypothesis", confidence=0.8, cid="c_0")],
        )
        assert r.passed is False
        assert r.skipped_hard_count == 1

    def test_skipped_soft_passes(self):
        r = validate_translation_integrity(
            self._z3r(skipped=[("c_0", "typecheck error")]),
            [_c("llm_hypothesis", confidence=0.5, soft=True, cid="c_0")],
        )
        assert r.passed is True

    def test_skipped_exact_counted(self):
        r = validate_translation_integrity(
            self._z3r(skipped=[("c_0", "Symbol not found: x")]),
            [_c("exact_mined", confidence=1.0, model_tier=0, cid="c_0")],
        )
        assert r.skipped_exact_count == 1
        assert r.undef_symbol_count == 1

    def test_empty_constraints(self):
        r = validate_translation_integrity(self._z3r(), [])
        assert r.passed is True
        assert r.total_constraints == 0
