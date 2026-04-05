from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from analysis.common import ida_wrapper
from analysis.common.debug import logger
from analysis.symbolic_object import Sink, TaintedVar
from analysis.exploit_report import Finding

from analysis.llvm_ir_emission.constraint_slice import build_taint_slice

def model_variable_set(
    sink: Sink,
    sink_callsite_addr: int,
    param_selection: set[TaintedVar],
    entrypoints: list[int],
    findings_dir: str | Path = "findings",
) -> tuple[Finding, list[str]]:
    logger.warning(
        "model_variable_set stub called for sink=%s callsite=0x%x params=%s",
        sink.label,
        sink_callsite_addr,
        [var.name for var in param_selection],
    )

    inferred_bin_name = ida_wrapper.input_file_name()
    findings_path = Path(findings_dir) / inferred_bin_name
    findings_path.mkdir(parents=True, exist_ok=True)
    sexpr_list: list[str] = []

    single_slice = build_taint_slice(
        sink_callsite_addr,
        param_selection,
        entrypoints,
        facts_output_dir=findings_path / "slices",
    )


    finding = Finding(
        sink_name=sink.label,
        sink_ea=sink_callsite_addr,
        driver_name=inferred_bin_name,
        variable_results=[],
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    output_path = findings_path / f"{sink.label}_{sink_callsite_addr}.json"
    finding.write(str(output_path))
    logger.info("model_variable_set stub wrote finding=%s", output_path)

    return finding, sexpr_list