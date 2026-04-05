from __future__ import annotations

from pathlib import Path

from analysis.common.debug import logger
from analysis.symbolic_object import TaintedVar, Sink

from analysis.sym_object_database import load_sink_definitions
from analysis.core import model_variable_set
from analysis.callgraph import prune_unreachable_entries_then_callsites
from analysis.exploit_report import has_non_inconclusive_user_trace, possible_sat_range

_ADDRESS_RANGE_THRESHOLD = 0x8000000000000


def run_detector(
    target: Path,
    findings_dir: Path,
    config_path: Path | None,
) -> list[dict]:
    """Entry point for runner: run arbitrary-write detector on target."""
    config_str = str(config_path) if config_path else None
    sinks = load_sink_definitions(config_str)
    results: list[dict] = []
    for sink in sinks:
        out = run(sink, Path(findings_dir), config_str)
        if out:
            results.extend(out)
    return results


def run(sink: Sink, findings_dir: str | Path, config_path: str | None = None) -> list[dict]:
    findings_dir = Path(findings_dir)

    results: list[dict] = []

    if "ARBITRARY_WRITE" not in sink.tags:
        return

    source_vars = sink.get_param_by_tag({"DATA_SOURCE"})
    sink_vars = sink.get_param_by_tag({"DATA_SINK"})

    if not source_vars or not sink_vars:
        logger.info(
            "arbitrary_write skipping sink=%s source_vars=%d sink_vars=%d",
            sink.label,
            len(source_vars),
            len(sink_vars),
        )
        return
    
    logger.info("arbitrary_write evaluating sink=%s", sink.label)

    all_vars = source_vars | sink_vars
    
    callsites, entrypoints = prune_unreachable_entries_then_callsites( sink.gather_initial_callsites(), sink )

    for callsite in callsites:
        logger.info("arbitrary_write tracing callsite=0x%x", callsite)

        finding, _ = model_variable_set(
            sink,
            callsite,
            all_vars,
            entrypoints,
            findings_dir / "arbitrary_write"
        )
        # Build var results keyed by variable for source/sink split
        def _vr_dict(vr):
            return {
                "status": vr.status.name,
                "requested_stop_point": vr.requested_stop_point.name if vr.requested_stop_point else None,
                "reached_stop_point": vr.reached_stop_point.name if vr.reached_stop_point else None,
            }
        var_results = {v.name: vr for vr in finding.variable_results for v in vr.variables}
        source_ok = all(
            has_non_inconclusive_user_trace(_vr_dict(vr))
            for v in source_vars
            for vr in [var_results.get(v.name)]
            if vr is not None
        )
        sink_ok = all(
            has_non_inconclusive_user_trace(_vr_dict(vr))
            for v in sink_vars
            for vr in [var_results.get(v.name)]
            if vr is not None
        )
        source_range_ok = all(
            possible_sat_range(item) >= _ADDRESS_RANGE_THRESHOLD
            for item in source_vars
        )
        sink_range_ok = all(
            possible_sat_range(item) >= _ADDRESS_RANGE_THRESHOLD
            for item in sink_vars
        )

        logger.info(
            "arbitrary_write decision sink=%s callsite=0x%x "
            "source_ok=%s sink_ok=%s source_range_ok=%s sink_range_ok=%s",
            sink.label,
            callsite,
            source_ok,
            sink_ok,
            source_range_ok,
            sink_range_ok,
        )

        if source_ok and sink_ok and source_range_ok and sink_range_ok:
            results.append(
                {
                    "type": "arbitrary_write",
                    "sink_name": sink.label,
                    "sink_callsite": f"0x{callsite:x}",
                    "finding": finding,
                }
            )

            logger.info(
                "arbitrary_write recorded finding sink=%s callsite=0x%x",
                sink.label,
                callsite,
            )

    logger.info("arbitrary_write complete findings=%d", len(results))

    return results