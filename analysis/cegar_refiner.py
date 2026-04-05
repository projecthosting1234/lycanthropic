from __future__ import annotations

import logging
from typing import Iterable

from analysis.symbolic_object import (
    VariableResult,
    VariableResultStatus,
    TaintedVar,
)

logger = logging.getLogger(__name__)

MAX_REFINEMENT_ROUNDS = 0


def refine(
    context: Iterable[object] | object,
    variables: Iterable[TaintedVar],
    findings_dir: str | None = None,
) -> VariableResult:
    logger.warning("cegar_refiner refine stubbed — returning inconclusive result")
    var_tuple = tuple(variables) if isinstance(variables, (list, tuple, set)) else (variables,)
    return VariableResult(
        variables=tuple(var_tuple),
        call_tree=None,
        is_sat=False,
        sat_model=None,
        sexpr="",
        refinement_rounds=0,
        status=VariableResultStatus.INCONCLUSIVE,
        requested_stop_point=None,
        reached_stop_point=None,
        stop_message="refiner disabled",
    )
from __future__ import annotations

import logging
from typing import Iterable

from analysis.symbolic_object import (
    VariableResult,
    VariableResultStatus,
    TaintedVar,
)

logger = logging.getLogger(__name__)

MAX_REFINEMENT_ROUNDS = 0


def refine(
    context: Iterable[object] | object,
    variables: Iterable[TaintedVar],
    findings_dir: str | None = None,
) -> VariableResult:
    logger.warning("cegar_refiner refine stubbed — returning inconclusive result")
    var_tuple = tuple(variables) if isinstance(variables, (list, tuple, set)) else (variables,)
    return VariableResult(
        variables=tuple(var_tuple),
        call_tree=None,
        is_sat=False,
        sat_model=None,
        sexpr="",
        refinement_rounds=0,
        status=VariableResultStatus.INCONCLUSIVE,
        requested_stop_point=None,
        reached_stop_point=None,
        stop_message="refiner disabled",
    )
from __future__ import annotations

import logging
from typing import Iterable

from analysis.symbolic_object import VariableResult, VariableResultStatus, TaintedVar

logger = logging.getLogger(__name__)

MAX_REFINEMENT_ROUNDS = 0


def refine(
    context: IRCallFlowContext,
    variables: set[TaintedVar] | list[TaintedVar],
    findings_dir: str | Path | None = None,
) -> VariableResult:
    chain = context.nodes
    vars_tuple = tuple(variables) if isinstance(variables, (set, list)) else (variables,)
    logger.info("refine start chain_len=%d vars=%d", len(chain), len(vars_tuple))

    for node in chain:
        node.constraints = ssa_pass(node.constraints, None)  # type: ignore[arg-type]

    encoder = Z3Encoder()
    free_var_map: dict[str, IRFunctionNode] = {}
    free_var_loop: dict[str, bool] = {}
    memo: dict[int, Expr] = {}
    branch_forcers: list[tuple[int, bool]] = []
    _findings_dir = Path(findings_dir) if findings_dir else None

    for node in chain:
        lift_nonchain_callee_nodes(chain, free_var_map, free_var_loop, node)
    encoder = _rebuild_solver(chain, branch_forcers)

    result = encoder.check()
    model = encoder.get_model() if result == z3.sat else {}
    sexpr = encoder.sexpr()
    rounds = 0

    logger.info("refine initial result=%s model_size=%d", result, len(model))

    # #region agent log
    try:
        from time import time as _agent_time
        _has_unsat = has_unsummarized_nonchain_callees(model, free_var_map, free_var_loop)
        _payload = {
            "sessionId": "25ab27",
            "runId": "pre-fix",
            "hypothesisId": "H1-H2",
            "location": "analysis/cegar_refiner.py:refine",
            "message": "refine initial state",
            "data": {
                "z3_result": str(result),
                "model_size": len(model),
                "free_var_map_size": len(free_var_map),
                "has_unsummarized": _has_unsat,
            },
            "timestamp": int(_agent_time() * 1000),
        }
        with open("debug-25ab27.log", "a", encoding="utf-8") as _f:
            import json as _agent_json
            _f.write(_agent_json.dumps(_payload) + "\n")
    except Exception:
        pass
    # #endregion agent log

    # Enter loop on unknown, or sat-with-unsummarized, or unsat-with-unsummarized on first check
    while rounds < MAX_REFINEMENT_ROUNDS and (
        result == z3.unknown
        or (result == z3.sat and has_unsummarized_nonchain_callees(model, free_var_map, free_var_loop))
        or (result == z3.unsat and rounds == 0 and has_unsummarized_nonchain_callees(model, free_var_map, free_var_loop))
    ):
        if rounds >= MAX_REFINEMENT_ROUNDS:
            logger.info("refine reached max rounds variables=%s", [v.name for v in vars_tuple])
            break

        logger.info(
            "\n\n%s\n%s\n REFINE ROUND %d  variables=%s \n%s\n%s",
            " " * 40,
            "=" * 72,
            rounds + 1,
            [v.name for v in vars_tuple],
            "=" * 72,
            " " * 40,
        )

        unsummarized_vals = get_unsummarized_nonchain_callees(model, free_var_map, free_var_loop)
        logger.info("unsummarized_vals=%s", unsummarized_vals)
        full_slice = _collect_all_slice_constraints(chain)
        if full_slice:
            first_node = next(_iter_slice_nodes(chain), None)
            func_name = first_node.func_name if first_node else ""
            pruned_slice, branch_forcers[:] = _prune_infeasible_paths(
                full_slice,
                func_name=func_name,
                accumulated_branch_forcers=branch_forcers,
            )
            kept = set(id(c) for c in pruned_slice)
            for n in _iter_slice_nodes(chain):
                n.constraints = [c for c in n.constraints if id(c) in kept]
        for free_name in unsummarized_vals:
            _build_summary_and_substitute(chain, free_var_map, memo, _findings_dir, rounds, free_name)
        encoder = _rebuild_solver(chain, branch_forcers)

        result = encoder.check()
        model = encoder.get_model() if result == z3.sat else {}
        sexpr = encoder.sexpr()
        rounds += 1

        logger.info("refine round complete round=%d result=%s model_size=%d", rounds, result, len(model))
        while True:
            K = input("press K to conitune")
            if K == 'K':
                break
    _repr = next(iter(vars_tuple), None)
    logger.info("refine complete variables=%s final_status=%s rounds=%d", [v.name for v in vars_tuple], "SAT" if result == z3.sat else "UNSAT", rounds)

    return VariableResult(
        variables=vars_tuple,
        call_tree=chain[0],
        is_sat=result == z3.sat,
        sat_model=model or None,
        sexpr=sexpr,
        refinement_rounds=rounds,
        status=VariableResultStatus.SAT if result == z3.sat else VariableResultStatus.UNSAT,
        requested_stop_point=_repr.trace_dest if _repr else None,
    )


def lift_nonchain_callee_nodes(
    chain: list[IRFunctionNode],
    free_var_map: dict[str, IRFunctionNode],
    free_var_loop: dict[str, bool],
    node: IRFunctionNode,
) -> None:
    logger.info("lift_nonchain_callee_nodes start node=%s  node callee sites dump=%s free_var_map var dump=%s", node.func_name, [f"{site.callee.func_name}" for site in node.callee_sites if site.callee is not None], [f"{name}: {node.func_name}" for name, node in free_var_map.items()])
    while True:
        K = input("press K to conitune")
        if K == 'K':
            break

    """Build non-chain callees from node.callee_sites (depth 1 only)."""
    try:
        node_index = next(i for i, n in enumerate(chain) if n is node)
        chain_callee_ea = chain[node_index + 1].func_ea if node_index + 1 < len(chain) else None
    except StopIteration:
        chain_callee_ea = None
    for i, site in enumerate(node.callee_sites):
        if site.callee is None:
            continue
        if chain_callee_ea is not None and site.callee.func_ea == chain_callee_ea:
            continue
        placeholder = site.callee
        callee_ea = placeholder.func_ea
        callee_node = LLVMIREmitter.decompile_recompile_pseudo(callee_ea, chain_callee_ea=None)
        callee_node.constraints = ssa_pass(callee_node.constraints, None)  # type: ignore[arg-type]
        callee_node.call_args = dict(placeholder.call_args)

        node.callee_sites[i] = Callsite(ret_expr=site.ret_expr, callee=callee_node, callsite_ea=site.callsite_ea, callee_ea=callee_ea)
        name = (site.ret_expr.symbol or "")
        if name:
            free_var_map[name] = callee_node
            free_var_loop[name] = getattr(placeholder, "loop_carried", False)


def get_unsummarized_nonchain_callees(
    model: dict[str, int],
    free_var_map: dict[str, IRFunctionNode],
    free_var_loop: dict[str, bool],
) -> list[str]:
    """Free var names (keys in free_var_map) that have no summary yet and are not loop-carried."""
    return [
        free_name
        for free_name, child in free_var_map.items()
        if child.return_summary is None
        and not free_var_loop.get(free_name, False)
    ]


def has_unsummarized_nonchain_callees(
    model: dict[str, int],
    free_var_map: dict[str, IRFunctionNode],
    free_var_loop: dict[str, bool],
) -> bool:
    return len(get_unsummarized_nonchain_callees(model, free_var_map, free_var_loop)) > 0


def _build_summary_and_substitute(
    chain: list[IRFunctionNode],
    free_var_map: dict[str, IRFunctionNode],
    memo: dict[int, Expr],
    findings_dir: Path | None,
    rounds: int,
    free_name: str,
) -> None:
    """Build return summary for one callee (if not memoized), write findings if requested, substitute into chain."""
    child = free_var_map[free_name]
    if child.func_ea in memo:
        summary = memo[child.func_ea]
    else:
        if findings_dir is not None:
            findings_dir.mkdir(parents=True, exist_ok=True)
            n = rounds + 1
            safe_name = re.sub(r"[^\w\-.]", "_", (child.func_name or "unknown"))
            path = findings_dir / f"{safe_name}_round{n}.json"
            path.write_text(json.dumps(_constraints_to_jsonable(child.constraints), indent=2), encoding="utf-8")
        summaries = LLVMIREmitter.build_return_summaries_for_callees([child])
        summary = summaries[child.func_ea]
        child.return_summary = summary
        memo[child.func_ea] = summary
    _substitute_in_chain(chain, free_name, summary)


def _substitute_in_chain(chain: list[IRFunctionNode], free_name: str, replacement: Expr) -> None:
    for node in chain:
        node.constraints = [
            Constraint(
                item.kind, _subst_expr(item.expr, free_name, replacement), item.parent_block_ea, item.ref,
                then_block_ea=item.then_block_ea, else_block_ea=item.else_block_ea, fallthru_ea=item.fallthru_ea,
            )
            for item in node.constraints
        ]
        _substitute_in_callee_sites(node.callee_sites, free_name, replacement)


def _substitute_in_callee_sites(
    callee_sites: list[Callsite], free_name: str, replacement: Expr
) -> None:
    for site in callee_sites:
        if site.callee is None:
            continue
        child = site.callee
        child.constraints = [
            Constraint(
                item.kind, _subst_expr(item.expr, free_name, replacement), item.parent_block_ea, item.ref,
                then_block_ea=item.then_block_ea, else_block_ea=item.else_block_ea, fallthru_ea=item.fallthru_ea,
            )
            for item in child.constraints
        ]
        if child.return_summary is not None:
            child.return_summary = _subst_expr(child.return_summary, free_name, replacement)
        _substitute_in_callee_sites(child.callee_sites, free_name, replacement)


def _subst_expr(expr: Expr, name: str, replacement: Expr) -> Expr:
    if expr.op in {ExprOp.SYMBOL, ExprOp.FRESH} and expr.symbol == name:
        return replacement

    if not expr.args:
        return expr

    return Expr(
        op=expr.op,
        args=tuple(_subst_expr(arg, name, replacement) for arg in expr.args),
        literal=expr.literal,
        symbol=expr.symbol,
        bitwidth=expr.bitwidth,
        ref=expr.ref,
        extract_hi=expr.extract_hi,
        extract_lo=expr.extract_lo,
    )


def _constraints_to_jsonable(constraints: list[Constraint]) -> list[dict]:
    """Convert constraints to JSON-serializable dicts (Expr/SourceInfo/Enum handled)."""

    def expr_to_dict(e: Expr) -> dict:
        return {
            "op": e.op.name,
            "args": [expr_to_dict(a) for a in e.args],
            "literal": e.literal,
            "symbol": e.symbol,
            "bitwidth": e.bitwidth,
            "ref": asdict(e.ref) if e.ref else None,
            "extract_hi": e.extract_hi,
            "extract_lo": e.extract_lo,
        }

    out = []
    for c in constraints:
        out.append({
            "kind": c.kind.name,
            "expr": expr_to_dict(c.expr),
            "node_ea": c.parent_block_ea,
            "ref": asdict(c.ref) if c.ref else None,
            "tainted_vars": list(c.tainted_vars),
            "block_ea": c.then_block_ea,
            "else_block_ea": c.else_block_ea,
            "fallthru_ea": c.fallthru_ea,
        })
    return out


def _iter_slice_nodes(chain: list[IRFunctionNode]) -> Iterator[IRFunctionNode]:
    """Yield every node in the slice: chain first, then each callee from callee_sites recursively."""
    for node in chain:
        yield node
        for site in node.callee_sites:
            if site.callee is not None:
                yield from _iter_slice_nodes([site.callee])


def _collect_all_slice_constraints(chain: list[IRFunctionNode]) -> list[Constraint]:
    """Collect all pipeline IR constraints from the entire taint slice (all chain nodes + all non-chain callees)."""
    return [c for node in _iter_slice_nodes(chain) for c in node.constraints]


def _prune_infeasible_paths(
    constraints: list[Constraint],
    *,
    func_name: str,
    accumulated_branch_forcers: list[tuple[int, bool]] | None = None,
) -> tuple[list[Constraint], list[tuple[int, bool]]]:
    """Prune constraints from infeasible branch sides via per-branch feasibility checks.
    For each branch i, force then (cond_i=True) and else (cond_i=False) one at a time;
    if UNSAT, that side is dead — record a path blocker (opposite condition) and prune
    constraints on that side. At most 2 * n_branches solver checks instead of 2^n paths.
    accumulated_branch_forcers from previous rounds are applied so dead branches stay dead."""
    logger.info("prune func_name=%s constraints=%d", func_name, len(constraints))
    n_before = len(constraints)
    accumulated_branch_forcers = accumulated_branch_forcers or []
    encoder = Z3Encoder(branch_forcers=accumulated_branch_forcers)
    for c in constraints:
        encoder.add_constraint(c)

    ite_conds = encoder.get_ite_conds()
    if not ite_conds:
        return (constraints, [])

    n_branches = len(ite_conds)
    total_possible_paths = 2**n_branches
    feasible_then: list[bool] = [True] * n_branches
    feasible_else: list[bool] = [True] * n_branches
    branch_forcers: list[tuple[int, bool]] = []

    for i, (cond_z3, then_ea, else_ea) in enumerate(ite_conds):
        logger.info("prune_infeasible_paths cond_z3=%s then_ea=%s else_ea=%s", cond_z3, then_ea, else_ea)
        # Force then: cond_i == True
        res_then = encoder.check_with_extra(cond_z3)
        if res_then != z3.sat:
            feasible_then[i] = False
            branch_forcers.append((i, False))  # force cond_i == False (never take then)
            logger.debug(
                "branch_feasibility[%d]: then=0x%x infeasible (UNSAT when forced)",
                i, then_ea if then_ea is not None else 0,
            )
        # Force else: cond_i == False
        res_else = encoder.check_with_extra(z3.Not(cond_z3))
        if res_else != z3.sat:
            feasible_else[i] = False
            branch_forcers.append((i, True))  # force cond_i == True (never take else)
            logger.debug(
                "branch_feasibility[%d]: else=%s infeasible (UNSAT when forced)",
                i, hex(else_ea) if else_ea is not None else "None",
            )

    feasible_sides = sum(feasible_then) + sum(feasible_else)
    logger.info(
        "paths: total_possible=%d feasible_branch_sides=%d branch_forcers=%d",
        total_possible_paths,
        feasible_sides,
        len(branch_forcers),
    )
    for i, (_cond, then_ea, else_ea) in enumerate(ite_conds):
        logger.info(
            "branch_feasibility[%d]: then=0x%x else=%s feasible_then=%s feasible_else=%s",
            i,
            then_ea if then_ea is not None else 0,
            hex(else_ea) if else_ea is not None else "None",
            feasible_then[i],
            feasible_else[i],
        )

    def on_feasible_side(c: Constraint) -> bool:
        if c.kind in (ConstraintKind.IT, ConstraintKind.ITE, ConstraintKind.SWITCH_COND):
            return True
        if c.kind != ConstraintKind.ASSIGN or c.then_block_ea is None:
            return True
        block_ea = c.then_block_ea
        for i, (_cond, then_ea, else_ea) in enumerate(ite_conds):
            if block_ea == then_ea and not feasible_then[i]:
                return False
            if else_ea is not None and block_ea == else_ea and not feasible_else[i]:
                return False
        return True

    pruned = [c for c in constraints if on_feasible_side(c)]
    # Merge with accumulated: once a branch is forced dead it stays dead across rounds.
    merged: dict[int, bool] = dict(accumulated_branch_forcers)
    for i, val in branch_forcers:
        merged[i] = val
    merged_list = list(merged.items())
    logger.info(
        "prune complete func_name=%s before=%d after=%d accumulated_forcers=%d",
        func_name,
        n_before,
        len(pruned),
        len(merged_list),
    )
    return (pruned, merged_list)


def _rebuild_solver(
    chain: list[IRFunctionNode],
    branch_forcers: list[tuple[int, bool]],
) -> Z3Encoder:
    encoder = Z3Encoder(branch_forcers=branch_forcers)
    for node in chain:
        for constraint in node.constraints:
            encoder.add_constraint(constraint)
    return encoder

