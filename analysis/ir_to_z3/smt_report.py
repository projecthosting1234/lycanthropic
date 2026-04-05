"""Structured report writer for SMT stage results.

Writes JSON artifacts summarizing constraints, solver results, unsat cores,
PoC witnesses, solver traces, models, and repair diffs to disk.
Also provides export_smt2() to produce a self-contained SMT-LIB2 script
for external solver verification (z3, cvc5, bitwuzla).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import z3

from analysis.ir_schema import Constraint, IR_SCHEMA_VERSION, ir_to_dict
from analysis.ir_to_z3.symbols import SymbolTable
from analysis.ir_to_z3.z3_translator import Z3TranslationResult

logger = logging.getLogger(__name__)


def export_smt2(
    z3_result: Z3TranslationResult,
    timeout_ms: int,
    finding_path: str = "",
) -> str:
    """Export translated constraints as an SMT-LIB2 script.

    Produces a self-contained .smt2 file that can be fed to any SMT-LIB2
    compliant solver (z3, cvc5, bitwuzla) for independent verification.

    Args:
        z3_result: Translation result containing Z3 expressions.
        timeout_ms: Solver timeout used (for header comment).
        finding_path: Optional finding path for provenance header.

    Returns:
        Complete SMT-LIB2 script as a string.
    """
    lines: list[str] = []

    # Header comment
    lines.append("; SMT-LIB2 export — WindowsExp SMT stage")
    lines.append(f"; IR schema version: {IR_SCHEMA_VERSION}")
    if finding_path:
        lines.append(f"; Finding: {finding_path}")
    lines.append(f"; Generated: {time.strftime('%Y-%m-%dT%H:%M:%S')}")
    lines.append(f"; Timeout: {timeout_ms}ms")
    lines.append(f"; Hard constraints: {len(z3_result.hard_constraint_ids)}")
    lines.append(f"; Soft constraints: {len(z3_result.soft_constraint_ids)}")
    lines.append(f"; Skipped constraints: {len(z3_result.skipped_constraints)}")
    lines.append(f"; Z3 variables: {len(z3_result.z3_vars)}")
    lines.append(f"; Deref functions: {len(z3_result.deref_functions)}")
    lines.append("")

    # Skipped constraints (provenance)
    if z3_result.skipped_constraints:
        lines.append("; --- Skipped constraints ---")
        for skip_id, skip_reason in z3_result.skipped_constraints:
            lines.append(f";   SKIPPED {skip_id}: {skip_reason}")
        lines.append("")

    # Translation diagnostics
    if z3_result.translation_diagnostics:
        lines.append("; --- Translation diagnostics ---")
        for diag in z3_result.translation_diagnostics[:30]:
            lines.append(f";   {diag}")
        if len(z3_result.translation_diagnostics) > 30:
            lines.append(f";   ... ({len(z3_result.translation_diagnostics) - 30} more)")
        lines.append("")

    # Soft constraint IDs (not asserted into solver)
    if z3_result.soft_constraint_ids:
        lines.append("; --- Soft constraints (not asserted) ---")
        for cid in z3_result.soft_constraint_ids:
            lines.append(f";   SOFT {cid}")
        lines.append("")

    # Detect logic: QF_UFBV if deref (uninterpreted) functions, else QF_BV
    logic = "QF_UFBV" if z3_result.deref_functions else "QF_BV"
    lines.append(f"(set-logic {logic})")
    lines.append("(set-option :produce-unsat-cores true)")
    lines.append("")

    # Solver sexpr (declarations + assertions)
    try:
        tmp_solver = z3.Solver()
        for cid in z3_result.hard_constraint_ids:
            if cid in z3_result.z3_exprs:
                tracker = z3.Bool(f"track_{cid}")
                tmp_solver.assert_and_track(z3_result.z3_exprs[cid], tracker)
        sexpr = tmp_solver.sexpr()
        if sexpr.strip():
            lines.append(sexpr)
    except Exception:
        lines.append("; (solver sexpr unavailable)")

    lines.append("")
    lines.append("(check-sat)")
    lines.append("(get-unsat-core)")
    lines.append("(get-model)")
    lines.append("")

    return "\n".join(lines)


@dataclass
class ReportPaths:
    result_json: Path
    constraints_json: Path
    smt2_file: Path | None
    unsat_core_json: Path | None
    poc_witness_json: Path | None
    solver_trace_json: Path | None = None
    model_json: Path | None = None
    repair_diff_json: Path | None = None
    summaries_json: Path | None = None


def write_smt_report(
    result,
    all_constraints: list[Constraint],
    symbol_table: SymbolTable,
    z3_result,
    output_dir: Path,
    finding_stem: str,
    smt2_text: str,
    solver_result=None,
    repair_result=None,
) -> ReportPaths:
    """Write structured report artifacts to output_dir.

    Args:
        result: SmtResult dataclass (uses dataclasses.asdict for serialization)
        all_constraints: All Constraint objects from the analysis
        symbol_table: The SymbolTable used for solving
        z3_result: Z3TranslationResult (for unsat core details)
        output_dir: Directory to write artifacts
        finding_stem: Base filename stem (e.g. "finding_0")
        smt2_text: Raw SMT2 text string
        solver_result: IncrementalSolveResult (optional, for trace/model)
        repair_result: RepairResult (optional, for repair diff)

    Returns:
        ReportPaths with paths to all written files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Result JSON
    result_path = output_dir / f"{finding_stem}_result.json"
    try:
        result_dict = asdict(result)
    except Exception:
        # Fallback for non-dataclass results
        result_dict = {"status": getattr(result, "status", "unknown")}
    _write_json(result_path, result_dict)

    # 2. Constraints JSON (all constraints + symbol table)
    constraints_path = output_dir / f"{finding_stem}_constraints.json"
    constraints_data = {
        "constraints": [ir_to_dict(c) for c in all_constraints],
        "symbol_table": symbol_table.to_dict(),
    }
    _write_json(constraints_path, constraints_data)

    # 3. SMT2 file
    smt2_path: Path | None = None
    if smt2_text:
        smt2_path = output_dir / f"{finding_stem}.smt2"
        smt2_path.write_text(smt2_text, encoding="utf-8")

    # 4. Unsat core JSON (if unsat)
    unsat_core_path: Path | None = None
    status = getattr(result, "status", "")
    if status == "unsat":
        unsat_core_ids = getattr(result, "unsat_core", [])
        if unsat_core_ids:
            c_index = {c.id: c for c in all_constraints}
            core_details = []
            for cid in unsat_core_ids:
                c = c_index.get(cid)
                if c is not None:
                    core_details.append(ir_to_dict(c))
                else:
                    core_details.append({"id": cid, "missing": True})

            unsat_core_path = output_dir / f"{finding_stem}_unsat_core.json"
            _write_json(unsat_core_path, {
                "unsat_core_ids": unsat_core_ids,
                "core_constraints": core_details,
            })

    # 5. PoC witness JSON (if sat)
    poc_path: Path | None = None
    if status == "sat":
        model = getattr(result, "model", {})
        if model:
            witness: dict[str, str | int] = {}
            for sym_name, val in model.items():
                if sym_name.startswith("track_"):
                    continue
                witness[sym_name] = val

            poc_path = output_dir / f"{finding_stem}_poc_witness.json"
            _write_json(poc_path, {
                "status": "sat",
                "witness": witness,
            })

    # 6. Solver trace JSON (per-node status + statistics)
    solver_trace_path: Path | None = None
    if solver_result is not None:
        solver_trace_path = _write_solver_trace(output_dir, finding_stem, solver_result)

    # 7. Model JSON (standalone model + deref interpretations)
    model_path: Path | None = None
    if solver_result is not None and getattr(solver_result, "model", None):
        model_path = _write_model(output_dir, finding_stem, solver_result)

    # 8. Repair diff JSON
    repair_diff_path: Path | None = None
    if repair_result is not None:
        repair_diff_path = _write_repair_diff(output_dir, finding_stem, repair_result)

    # 9. Node summaries JSON
    summaries_path: Path | None = None
    node_summaries = getattr(result, "diagnostics", {}).get("node_summaries")
    if node_summaries:
        summaries_path = output_dir / f"{finding_stem}_summaries.json"
        _write_json(summaries_path, node_summaries)

    report = ReportPaths(
        result_json=result_path,
        constraints_json=constraints_path,
        smt2_file=smt2_path,
        unsat_core_json=unsat_core_path,
        poc_witness_json=poc_path,
        solver_trace_json=solver_trace_path,
        model_json=model_path,
        repair_diff_json=repair_diff_path,
        summaries_json=summaries_path,
    )

    logger.info("[+] SMT report written: %s", result_path.parent)
    return report


def _write_solver_trace(output_dir: Path, finding_stem: str, solver_result) -> Path:
    """Write per-node solver trace and Z3 statistics."""
    path = output_dir / f"{finding_stem}_solver_trace.json"
    quality = getattr(solver_result, "quality", "unknown_incomplete")
    _write_json(path, {
        "per_node_status": [asdict(ns) for ns in solver_result.per_node_status],
        "solver_statistics": solver_result.solver_statistics,
        "unconstrained_symbols": solver_result.unconstrained_symbols,
        "accepted_soft_ids": getattr(solver_result, "accepted_soft_ids", []),
        "rejected_soft_ids": getattr(solver_result, "rejected_soft_ids", []),
        "soft_objective_value": getattr(solver_result, "soft_objective_value", 0),
        "soft_objective_max": getattr(solver_result, "soft_objective_max", 0),
        "quality": quality.value if hasattr(quality, 'value') else str(quality),
    })
    return path


def _write_model(output_dir: Path, finding_stem: str, solver_result) -> Path:
    """Write standalone model with deref interpretations."""
    path = output_dir / f"{finding_stem}_model.json"
    _write_json(path, {
        "model": {k: v for k, v in solver_result.model.items() if not k.startswith("track_")},
        "model_representations": solver_result.model_representations,
        "deref_values": solver_result.deref_values,
    })
    return path


def _write_repair_diff(output_dir: Path, finding_stem: str, repair_result) -> Path | None:
    """Write repair attempt history and constraint mutations."""
    if repair_result is None:
        return None
    path = output_dir / f"{finding_stem}_repair_diff.json"
    _write_json(path, {
        "original_status": repair_result.original_status,
        "final_status": repair_result.final_status,
        "strategies_tried": repair_result.strategies_tried,
        "constraints_dropped": repair_result.constraints_dropped,
        "constraints_weakened": repair_result.constraints_weakened,
        "guardrail_vetoes": repair_result.guardrail_vetoes,
        "attempts": [asdict(a) for a in repair_result.attempts],
    })
    return path


def _write_json(path: Path, data: dict) -> None:
    """Write JSON with consistent formatting."""
    path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )
