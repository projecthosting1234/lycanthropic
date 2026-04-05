"""Automated constraint repair loop (Step 14).

When solve_incremental() returns unsat or unknown, attempt to repair the
constraint set by relaxing or removing low-confidence constraints, then re-solve.

Three strategies tried in order:
  0. Drop soft — remove droppable constraints from unsat core
  1. LLM IR patch — send diagnostics to LLM, apply vetted repair actions
  2. Re-extract — remove all LLM constraints for failing node, re-extract

Never silently deletes high-confidence mined constraints.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from analysis.ir_schema import (
    Constraint,
    Expr,
    PROTECTED_KINDS,
    SolveQuality,
    classify_solve_quality,
    is_exact,
    ir_to_dict,
    Symbol,
)
from .solver import IncrementalSolveResult, solve_incremental
from .symbols import SymbolTable
from analysis.ir_to_z3.z3_translator import Z3TranslationResult, translate_to_z3
from analysis.common.llm import call_llm, load_llm_config

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from analysis.common.llm import load_prompt

# Alias for backward compat within this module
_PROTECTED_KINDS = PROTECTED_KINDS


def extract_node_constraints(*args, **kwargs) -> tuple[list[Constraint], list[Symbol]]:
    logger.info("extract_node_constraints stub: returning empty lists")
    return [], []


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

@dataclass
class DiagnosticPacket:
    """Bundles failing constraint context for the LLM repair prompt."""

    failing_constraint_ids: list[str]
    unsat_core: list[str]
    reason_unknown: str
    failing_node_ea: str
    failing_node_name: str
    symbol_table_summary: str
    hard_ids: list[str]
    soft_ids: list[str]
    per_node_status_summary: str
    translator_diagnostics: str


@dataclass
class RepairAction:
    """One atomic mutation to a constraint set."""

    action: str  # drop | weaken_bound | mark_soft | lower_confidence | replace_expr
    constraint_id: str
    reason: str = ""
    new_literal: int | None = None
    new_bitwidth: int | None = None
    new_confidence: float | None = None
    new_expr_dict: dict | None = None


@dataclass
class RepairAttempt:
    """Record of one repair attempt."""

    strategy: str
    iteration: int
    actions: list[RepairAction]
    status_after: str  # sat | unsat | unknown
    elapsed_ms: float = 0.0
    cache_hit: bool = False
    guardrail_vetoes: int = 0


@dataclass
class RepairResult:
    """Complete result of the repair loop."""

    original_status: str
    final_status: str
    attempts: list[RepairAttempt] = field(default_factory=list)
    constraints_dropped: int = 0
    constraints_weakened: int = 0
    guardrail_vetoes: int = 0
    strategies_tried: list[str] = field(default_factory=list)
    solver_result: IncrementalSolveResult | None = None
    quality: SolveQuality = SolveQuality.UNKNOWN_INCOMPLETE


# ------------------------------------------------------------------
# RepairGuardrail
# ------------------------------------------------------------------

class RepairGuardrail:
    """Decides which constraints are protected, relaxable, or droppable."""

    def is_protected(self, c: Constraint) -> bool:
        """True if constraint must never be modified."""
        if "mined" in c.id and c.confidence == 1.0 and c.model_tier == 0 and not c.soft:
            return True
        if c.kind in _PROTECTED_KINDS:
            return True
        # Exact-lane facts at full confidence are protected
        if is_exact(c) and c.confidence >= 0.95 and c.model_tier == 0 and not c.soft:
            return True
        return False

    def is_droppable(self, c: Constraint) -> bool:
        """True if constraint can be removed entirely."""
        if self.is_protected(c):
            return False
        if c.soft:
            return True
        if c.confidence < 0.8:
            return True
        if "llm" in c.id and c.model_tier >= 1:
            return True
        if "mined" in c.id and c.model_tier >= 1:
            return True
        return False

    def is_relaxable(self, c: Constraint) -> bool:
        """True if constraint can be weakened but not dropped."""
        if self.is_protected(c):
            return False
        return True

    def vet_action(self, action: RepairAction, constraint: Constraint) -> tuple[bool, str]:
        """Validate a proposed repair action against guardrails.

        Returns (allowed, reason).
        """
        if self.is_protected(constraint):
            return False, f"constraint {constraint.id} is protected (kind={constraint.kind}, confidence={constraint.confidence})"

        if action.action == "drop":
            if not self.is_droppable(constraint):
                return False, f"constraint {constraint.id} is not droppable (confidence={constraint.confidence}, soft={constraint.soft})"
            return True, "droppable"

        if action.action in ("weaken_bound", "mark_soft", "lower_confidence", "replace_expr"):
            if not self.is_relaxable(constraint):
                return False, f"constraint {constraint.id} is not relaxable"
            return True, "relaxable"

        return False, f"unknown action type: {action.action}"


# ------------------------------------------------------------------
# RepairCache
# ------------------------------------------------------------------

class RepairCache:
    """Hash-based JSON file cache for LLM repair responses.

    Only caches Strategy 1 (LLM) responses; Strategies 0 and 2 are deterministic.
    TTL: 7 days.
    """

    TTL_SECONDS = 7 * 24 * 3600

    def __init__(self, cache_dir: Path | None = None):
        if cache_dir is None:
            cache_dir = Path.cwd() / ".repair_cache"
        self._dir = cache_dir

    def _make_key(self, failing_node_ea: str, core_ids: list[str], constraint_fingerprint: str = "") -> str:
        """Deterministic cache key from failing node + unsat core + fingerprint."""
        from analysis.ir_schema import IR_SCHEMA_VERSION
        payload = f"{failing_node_ea}|{'|'.join(sorted(core_ids))}|{IR_SCHEMA_VERSION}|{constraint_fingerprint}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def get(self, key: str) -> list[dict] | None:
        """Retrieve cached actions, or None if miss/expired."""
        if not self._dir.exists():
            return None
        path = self._dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            ts = data.get("timestamp", 0)
            if time.time() - ts > self.TTL_SECONDS:
                path.unlink(missing_ok=True)
                return None
            return data.get("actions", [])
        except (json.JSONDecodeError, OSError):
            return None

    def put(self, key: str, actions: list[dict]) -> None:
        """Store actions in cache."""
        self._dir.mkdir(parents=True, exist_ok=True)
        data = {"timestamp": time.time(), "actions": actions}
        path = self._dir / f"{key}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _constraint_fingerprint(constraints: list[Constraint]) -> str:
    """Hash of hard constraint IDs + count for cache keying."""
    ids = sorted(c.id for c in constraints if not c.soft)
    return hashlib.sha256("|".join(ids).encode()).hexdigest()[:12]


def _build_constraint_index(constraints: list[Constraint]) -> dict[str, Constraint]:
    """Build {id: Constraint} lookup."""
    return {c.id: c for c in constraints}


def _expr_references_suspect(expr: Expr, symbol_table: SymbolTable) -> bool:
    """True if any symbol in expr is an overtaint suspect."""
    if expr.symbol is not None:
        if symbol_table.is_overtaint_suspect(expr.symbol):
            return True
    for arg in expr.args:
        if _expr_references_suspect(arg, symbol_table):
            return True
    return False


def _classify_core_taint(
    unsat_core: list[str],
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
) -> str:
    """Classify whether the unsat core is dominated by overtaint-suspect constraints."""
    index = _build_constraint_index(all_constraints)
    suspect_count = 0
    total = 0
    for cid in unsat_core:
        c = index.get(cid)
        if c is None:
            continue
        total += 1
        if _expr_references_suspect(c.expr, symbol_table):
            suspect_count += 1
    if total == 0:
        return "mixed"
    return "overtaint_dominated" if suspect_count / total > 0.5 else "mixed"


def _format_symbol_table_summary(symbol_table: SymbolTable) -> str:
    """Concise text summary for the repair prompt."""
    lines = []
    for sym, expr in sorted(symbol_table.symbols.items(), key=lambda p: p[0].name):
        lines.append(f"  {sym.name}: {sym.sort.__name__}({expr.bitwidth}) domain={sym.domain}")
    return "\n".join(lines) if lines else "(empty)"


def _format_per_node_summary(solver_result: IncrementalSolveResult) -> str:
    """Format per-node status for prompt."""
    lines = []
    for ns in solver_result.per_node_status:
        lines.append(f"  {ns.ea} {ns.name}: {ns.status} (+{ns.constraints_added} constraints) {ns.reason}")
    return "\n".join(lines) if lines else "(none)"


def _find_failing_node(solver_result: IncrementalSolveResult) -> tuple[str, str]:
    """Find the first node that failed (unsat/unknown)."""
    for ns in solver_result.per_node_status:
        if ns.status in ("unsat", "unknown"):
            return ns.ea, ns.name
    return "unknown", "unknown"


def _re_translate_and_solve(
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    chain: list[dict],
    timeout_ms: int,
) -> tuple[Z3TranslationResult, IncrementalSolveResult]:
    """Full re-translation + solve (Z3 assert_and_track doesn't support removal)."""
    z3_result = translate_to_z3(all_constraints, symbol_table)
    solver_result = solve_incremental(z3_result, all_constraints, chain, timeout_ms)
    return z3_result, solver_result


def _apply_action(
    action: RepairAction,
    constraints: list[Constraint],
    index: dict[str, Constraint],
    symbol_table: SymbolTable | None = None,
) -> str:
    """Apply a single repair action. Returns description of what was done."""
    c = index.get(action.constraint_id)
    if c is None:
        return f"constraint {action.constraint_id} not found"

    # Exact-lane integrity assertion: pristine exact facts must not be mutated.
    # The guardrail should have blocked this; the assertion catches guardrail bugs.
    if __debug__ and is_exact(c) and c.confidence >= 0.95 and c.model_tier == 0 and not c.soft:
        assert False, (
            f"exact-lane violation: {action.action} on {c.id} "
            f"(fact_class={c.fact_class}, conf={c.confidence})"
        )

    if action.action == "drop":
        constraints[:] = [cc for cc in constraints if cc.id != action.constraint_id]
        index.pop(action.constraint_id, None)
        return f"dropped {action.constraint_id}"

    if action.action == "weaken_bound":
        if action.new_literal is not None:
            # Find literal in expression and replace
            _replace_literal(c.expr, action.new_literal, action.new_bitwidth)
            return f"weakened bound in {action.constraint_id} to {action.new_literal}"

    if action.action == "mark_soft":
        c.soft = True
        if action.new_confidence is not None:
            c.confidence = action.new_confidence
        return f"marked {action.constraint_id} as soft"

    if action.action == "lower_confidence":
        if action.new_confidence is not None:
            c.confidence = action.new_confidence
            return f"lowered confidence of {action.constraint_id} to {action.new_confidence}"

    if action.action == "replace_expr":
        if action.new_expr_dict is not None:
            try:
                c.expr = Expr.from_dict(action.new_expr_dict)
                return f"replaced expr of {action.constraint_id}"
            except Exception as e:
                return f"failed to replace expr of {action.constraint_id}: {e}"

    return f"no-op for {action.constraint_id}"


def _replace_literal(expr: Expr, new_value: int, new_bitwidth: int | None) -> bool:
    """Replace the comparison bound literal in a constraint expression.

    For comparison ops (eq, ne, bvult, etc.) with a literal on one side,
    replaces that literal specifically rather than the first literal found
    in an arbitrary depth-first walk.  Falls back to first-literal replacement
    only when no comparison pattern is detected.
    """
    # If this is a comparison op with a literal arg, target that literal directly
    _CMP_OPS = {"eq", "ne", "bvult", "bvule", "bvugt", "bvuge",
                "bvslt", "bvsle", "bvsgt", "bvsge"}
    if expr.op in _CMP_OPS and len(expr.args) == 2:
        # Prefer the right-hand side literal (the bound in "sym < bound")
        for arg in reversed(expr.args):
            if arg.literal is not None and not isinstance(arg.literal, bool):
                arg.literal = new_value
                if new_bitwidth is not None:
                    arg.bitwidth = new_bitwidth
                return True

    # Fallback: depth-first search for the first non-bool literal
    if expr.literal is not None and not isinstance(expr.literal, bool):
        expr.literal = new_value
        if new_bitwidth is not None:
            expr.bitwidth = new_bitwidth
        return True
    for arg in expr.args:
        if _replace_literal(arg, new_value, new_bitwidth):
            return True
    return False


# ------------------------------------------------------------------
# Strategy 0: Drop soft constraints from unsat core
# ------------------------------------------------------------------

def _strategy_drop_soft(
    solver_result: IncrementalSolveResult,
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    chain: list[dict],
    timeout_ms: int,
    guardrail: RepairGuardrail,
) -> RepairAttempt:
    """Remove droppable constraints from the unsat core, sorted by confidence ascending."""
    t0 = time.perf_counter()
    index = _build_constraint_index(all_constraints)

    # Find droppable constraints in the unsat core
    core_ids = solver_result.unsat_core
    droppable: list[tuple[float, str]] = []
    for cid in core_ids:
        c = index.get(cid)
        if c and guardrail.is_droppable(c):
            droppable.append((c.confidence, cid))

    # Early return: nothing to drop -> no re-translate/solve
    if not droppable:
        return RepairAttempt(
            strategy="drop_soft",
            iteration=0,
            actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Sort by confidence ascending (drop least-confident first)
    droppable.sort(key=lambda x: x[0])

    actions: list[RepairAction] = []
    for conf, cid in droppable:
        c = index.get(cid)
        if c is None:
            continue
        # Soften instead of dropping: the MaxSMT solver will find the
        # optimal subset. Lower confidence so the weight reflects reduced
        # trustworthiness from appearing in the unsat core.
        new_conf = max(0.3, conf * 0.5)
        action = RepairAction(
            action="mark_soft",
            constraint_id=cid,
            reason=f"softened from unsat core ({conf:.2f} -> {new_conf:.2f})",
            new_confidence=new_conf,
        )
        allowed, reason = guardrail.vet_action(action, c)
        if allowed:
            _apply_action(action, all_constraints, index, symbol_table)
            actions.append(action)

    # No actions survived guardrail vetting -> skip re-translate/solve
    if not actions:
        return RepairAttempt(
            strategy="drop_soft",
            iteration=0,
            actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Re-translate and re-solve
    _, new_result = _re_translate_and_solve(all_constraints, symbol_table, chain, timeout_ms)

    return RepairAttempt(
        strategy="drop_soft",
        iteration=0,
        actions=actions,
        status_after=new_result.status,
        elapsed_ms=(time.perf_counter() - t0) * 1000,
    )


# ------------------------------------------------------------------
# Strategy 1: LLM IR patch
# ------------------------------------------------------------------

def _strategy_llm_patch(
    solver_result: IncrementalSolveResult,
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    chain: list[dict],
    timeout_ms: int,
    guardrail: RepairGuardrail,
    cache: RepairCache,
    z3_result: Z3TranslationResult,
) -> RepairAttempt:
    """Send diagnostics to LLM, parse repair actions, vet and apply."""
    t0 = time.perf_counter()
    index = _build_constraint_index(all_constraints)

    cfg = load_llm_config()
    if not cfg:
        return RepairAttempt(
            strategy="llm_patch",
            iteration=1,
            actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    provider, api_key, model = cfg
    failing_ea, failing_name = _find_failing_node(solver_result)

    # Check cache
    fp = _constraint_fingerprint(all_constraints)
    cache_key = cache._make_key(failing_ea, solver_result.unsat_core, fp)
    cached_actions = cache.get(cache_key)
    if cached_actions is not None:
        # Apply cached actions
        actions = _parse_repair_actions(cached_actions)
        vetted, _ = _vet_and_apply_actions(actions, all_constraints, index, guardrail, symbol_table)
        if vetted:
            _, new_result = _re_translate_and_solve(all_constraints, symbol_table, chain, timeout_ms)
            return RepairAttempt(
                strategy="llm_patch",
                iteration=1,
                actions=vetted,
                status_after=new_result.status,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                cache_hit=True,
            )

    # Build diagnostic packet
    hard_ids = [c.id for c in all_constraints if guardrail.is_protected(c)]
    soft_ids = [c.id for c in all_constraints if not guardrail.is_protected(c)]

    # Serialize unsat core constraints
    core_constraints = [index[cid] for cid in solver_result.unsat_core if cid in index]
    unsat_core_json = json.dumps([ir_to_dict(c) for c in core_constraints], indent=2)

    reason_unknown = ""
    if solver_result.status == "unknown":
        for ns in solver_result.per_node_status:
            if ns.status == "unknown":
                reason_unknown = f"Reason unknown: {ns.reason}"
                break

    # Load and format prompt
    try:
        template = load_prompt("08-repair-constraints.txt")
    except FileNotFoundError:
        return RepairAttempt(
            strategy="llm_patch",
            iteration=1,
            actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    translator_diags = ""
    if z3_result.translation_diagnostics:
        translator_diags = "\n".join(z3_result.translation_diagnostics[:20])

    prompt = (
        template
        .replace("{status}", solver_result.status)
        .replace("{failing_node_ea}", failing_ea)
        .replace("{failing_node_name}", failing_name)
        .replace("{reason_unknown}", reason_unknown)
        .replace("{unsat_core_json}", unsat_core_json)
        .replace("{symbol_table_summary}", _format_symbol_table_summary(symbol_table))
        .replace("{hard_ids_summary}", "\n".join(f"  {cid}" for cid in hard_ids[:30]) or "(none)")
        .replace("{soft_ids_summary}", "\n".join(f"  {cid}" for cid in soft_ids[:30]) or "(none)")
        .replace("{per_node_status_summary}", _format_per_node_summary(solver_result))
        .replace("{translator_diagnostics}", translator_diags or "(none)")
    )

    logger.info("[*] Step 14: Asking LLM (%s/%s) for constraint repair...", provider, model)

    try:
        text = call_llm(provider, api_key, model, prompt, max_tokens=50000)
        if not text or not text.strip():
            return RepairAttempt(
                strategy="llm_patch", iteration=1, actions=[],
                status_after=solver_result.status,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        from analysis.common.json_repair import strip_code_fences
        text = strip_code_fences(text)

        result_data = json.loads(text)
        raw_actions = result_data.get("actions", [])
        analysis = result_data.get("analysis", "")

        # Cache the response
        cache.put(cache_key, raw_actions)

        # Check for genuine infeasibility
        if not raw_actions and "genuine" in analysis.lower():
            return RepairAttempt(
                strategy="llm_patch", iteration=1, actions=[],
                status_after=solver_result.status,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        actions = _parse_repair_actions(raw_actions)
        vetted, veto_count = _vet_and_apply_actions(actions, all_constraints, index, guardrail, symbol_table)

        if not vetted:
            return RepairAttempt(
                strategy="llm_patch", iteration=1, actions=[],
                status_after=solver_result.status,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
                guardrail_vetoes=veto_count,
            )

        _, new_result = _re_translate_and_solve(all_constraints, symbol_table, chain, timeout_ms)
        return RepairAttempt(
            strategy="llm_patch",
            iteration=1,
            actions=vetted,
            status_after=new_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
            guardrail_vetoes=veto_count,
        )

    except (json.JSONDecodeError, KeyError, Exception) as e:
        import traceback
        logger.warning("[!] LLM repair failed: %s", e)
        traceback.print_exc()
        return RepairAttempt(
            strategy="llm_patch", iteration=1, actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )


def _parse_repair_actions(raw: list[dict]) -> list[RepairAction]:
    """Parse raw action dicts into RepairAction objects."""
    actions = []
    for ad in raw:
        try:
            actions.append(RepairAction(
                action=ad["action"],
                constraint_id=ad["constraint_id"],
                reason=ad.get("reason", ""),
                new_literal=ad.get("new_literal"),
                new_bitwidth=ad.get("new_bitwidth"),
                new_confidence=ad.get("new_confidence"),
                new_expr_dict=ad.get("new_expr_dict"),
            ))
        except (KeyError, TypeError):
            continue
    return actions


def _vet_and_apply_actions(
    actions: list[RepairAction],
    all_constraints: list[Constraint],
    index: dict[str, Constraint],
    guardrail: RepairGuardrail,
    symbol_table: SymbolTable | None = None,
) -> tuple[list[RepairAction], int]:
    """Vet each action against guardrails and apply if allowed.

    Returns (applied_actions, veto_count).
    """
    applied = []
    vetoed = 0
    for action in actions:
        c = index.get(action.constraint_id)
        if c is None:
            continue
        allowed, reason = guardrail.vet_action(action, c)
        if allowed:
            _apply_action(action, all_constraints, index, symbol_table)
            applied.append(action)
        else:
            vetoed += 1
            logger.warning("[!] Guardrail vetoed: %s on %s: %s", action.action, action.constraint_id, reason)
    return applied, vetoed


# ------------------------------------------------------------------
# Strategy 2: Re-extract LLM constraints for failing node
# ------------------------------------------------------------------

def _strategy_reextract(
    solver_result: IncrementalSolveResult,
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    chain: list[dict],
    timeout_ms: int,
    slices: dict[str, str],
    chain_facts: list[dict | None],
    taint_chain: list[dict],
    ioctl_codes: list[str],
    finding: dict,
) -> RepairAttempt:
    """Remove ALL LLM constraints for failing node, re-extract with context."""
    t0 = time.perf_counter()
    failing_ea, failing_name = _find_failing_node(solver_result)

    # Remove all LLM constraints for the failing node
    prefix = f"c_llm_{failing_ea}_"
    removed = [c.id for c in all_constraints if c.id.startswith(prefix)]
    all_constraints[:] = [c for c in all_constraints if not c.id.startswith(prefix)]

    if not removed:
        return RepairAttempt(
            strategy="reextract",
            iteration=2,
            actions=[],
            status_after=solver_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Find the chain node for the failing EA
    node = None
    node_idx = None
    for idx, n in enumerate(chain[1:], start=1):
        if n["ea"].lower() == failing_ea:
            node = n
            node_idx = idx
            break

    if node is None or failing_ea not in slices:
        # Can't re-extract, just re-solve without the removed constraints
        _, new_result = _re_translate_and_solve(all_constraints, symbol_table, chain, timeout_ms)
        actions = [RepairAction(action="drop", constraint_id=cid, reason="re-extract: removed for re-extraction") for cid in removed]
        return RepairAttempt(
            strategy="reextract",
            iteration=2,
            actions=actions,
            status_after=new_result.status,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Get context for re-extraction
    slice_text = slices[failing_ea]
    cf = chain_facts[node_idx] if node_idx < len(chain_facts) else None

    # Find taint_chain entry
    tc_as_caller = None
    for tc in taint_chain:
        caller = tc.get("caller", {})
        if caller.get("ea", "").lower() == failing_ea:
            tc_as_caller = tc
            break

    callee_name = chain[node_idx - 1]["name"] if node_idx > 0 else None

    # Get existing mined constraints for this node
    mined = [c for c in all_constraints if "mined" in c.id and c.parent_block_ea == failing_ea]

    # Re-extract
    new_constraints, new_symbols = extract_node_constraints(
        node_ea=failing_ea,
        node_name=failing_name,
        slice_text=slice_text,
        chain_facts=cf,
        taint_chain_as_caller=tc_as_caller,
        mined_constraints=mined,
        symbol_table=symbol_table,
        callee_name_in_chain=callee_name,
    )

    # Add new symbols
    for sym in new_symbols:
        try:
            symbol_table.add(sym)
        except ValueError:
            pass

    all_constraints.extend(new_constraints)

    # Re-solve
    _, new_result = _re_translate_and_solve(all_constraints, symbol_table, chain, timeout_ms)

    actions = [RepairAction(action="drop", constraint_id=cid, reason="re-extract: removed for re-extraction") for cid in removed]
    return RepairAttempt(
        strategy="reextract",
        iteration=2,
        actions=actions,
        status_after=new_result.status,
        elapsed_ms=(time.perf_counter() - t0) * 1000,
    )


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------

def attempt_repair(
    solver_result: IncrementalSolveResult,
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    chain: list[dict],
    z3_result: Z3TranslationResult,
    timeout_ms: int,
    slices: dict[str, str],
    chain_facts: list[dict | None],
    taint_chain: list[dict],
    ioctl_codes: list[str],
    finding: dict,
    max_retries: int = 3,
) -> RepairResult:
    """Attempt to repair an unsat/unknown constraint set.

    Tries up to 3 strategies in order:
      0. Drop soft constraints from unsat core
      1. LLM IR patch (with cache)
      2. Re-extract LLM constraints for failing node

    Returns RepairResult with the final status and all attempts.
    """
    original_status = solver_result.status
    result = RepairResult(
        original_status=original_status,
        final_status=original_status,
    )

    guardrail = RepairGuardrail()
    cache = RepairCache()
    current_result = solver_result
    current_timeout = timeout_ms

    logger.info("[*] Repair: starting from %s, unsat core=%d constraints",
                original_status, len(solver_result.unsat_core))

    core_taint_class = _classify_core_taint(
        solver_result.unsat_core, all_constraints, symbol_table,
    )
    if core_taint_class == "overtaint_dominated":
        logger.info("[*] Repair: unsat core is overtaint-dominated")

    # Snapshot constraints before the repair loop. All strategies mutate
    # the working copy; originals are preserved if repair fails.
    working_constraints = Constraint.snapshot_list(all_constraints)

    for iteration in range(min(max_retries, 3)):
        if current_result.status == "sat":
            break

        # For unknown (timeout), increase timeout by 50%
        if current_result.status == "unknown" and iteration > 0:
            current_timeout = min(int(current_timeout * 1.5), timeout_ms * 2)

        if iteration == 0:
            # Strategy 0: Drop soft
            attempt = _strategy_drop_soft(
                current_result, working_constraints, symbol_table, chain,
                current_timeout, guardrail,
            )
            result.strategies_tried.append("drop_soft")

        elif iteration == 1:
            # Skip LLM patch if core is overtaint-dominated
            if core_taint_class == "overtaint_dominated":
                result.strategies_tried.append("llm_patch (skipped: overtaint-dominated)")
                continue

            # Check if all core constraints are protected — skip LLM if so
            index = _build_constraint_index(working_constraints)
            core_ids = current_result.unsat_core
            all_protected = all(
                guardrail.is_protected(index[cid])
                for cid in core_ids
                if cid in index
            )
            if all_protected and core_ids:
                result.strategies_tried.append("llm_patch (skipped: all protected)")
                continue

            attempt = _strategy_llm_patch(
                current_result, working_constraints, symbol_table, chain,
                current_timeout, guardrail, cache, z3_result,
            )
            result.strategies_tried.append("llm_patch")

            # If LLM returns empty actions with genuine infeasibility, skip strategy 2
            if not attempt.actions and attempt.status_after != "sat":
                result.attempts.append(attempt)
                result.guardrail_vetoes += attempt.guardrail_vetoes
                break

        elif iteration == 2:
            # Strategy 2: Re-extract
            attempt = _strategy_reextract(
                current_result, working_constraints, symbol_table, chain,
                current_timeout, slices, chain_facts, taint_chain,
                ioctl_codes, finding,
            )
            result.strategies_tried.append("reextract")
        else:
            break

        result.attempts.append(attempt)
        result.guardrail_vetoes += attempt.guardrail_vetoes

        logger.info("[*] Repair strategy %s: %s -> %s (%d actions, %.0fms%s)",
                    attempt.strategy, current_result.status, attempt.status_after,
                    len(attempt.actions), attempt.elapsed_ms,
                    ", cache hit" if attempt.cache_hit else "")

        # Count actions
        for a in attempt.actions:
            if a.action == "drop":
                result.constraints_dropped += 1
            else:
                result.constraints_weakened += 1

        # Update current result for next iteration
        if attempt.status_after == "sat":
            result.final_status = "sat"
            # Get the actual solver result from the working copy
            z3r, sr = _re_translate_and_solve(working_constraints, symbol_table, chain, current_timeout)
            result.solver_result = sr
            # Commit: replace originals with the successfully repaired copy
            all_constraints[:] = working_constraints
            break
        else:
            # Re-solve to get updated state for next strategy
            z3r, current_result = _re_translate_and_solve(working_constraints, symbol_table, chain, current_timeout)
            z3_result = z3r
            result.final_status = current_result.status

    # If we exhausted strategies without sat, store the latest result.
    # Originals are untouched — working_constraints is discarded.
    if result.solver_result is None and current_result is not solver_result:
        result.solver_result = current_result

    # Classify quality from the best solver result available
    if result.solver_result is not None:
        result.quality = result.solver_result.quality
    else:
        result.quality = classify_solve_quality(
            result.final_status, [], [], [],
        )

    if result.final_status != result.original_status:
        logger.info("[+] Repair: %s -> %s (quality=%s, dropped=%d, weakened=%d, vetoed=%d)",
                    result.original_status, result.final_status, result.quality.value,
                    result.constraints_dropped, result.constraints_weakened,
                    result.guardrail_vetoes)
    else:
        logger.info("[-] Repair: stayed %s (quality=%s) after %d strategies",
                    result.final_status, result.quality.value, len(result.strategies_tried))

    return result
