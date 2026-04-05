from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from analysis.common.debug import logger
from analysis.common import ida_wrapper
from analysis.llvm_ir_emission.emitter import LLVMIREmitter
from analysis.symbolic_object import TraceDestination, TaintedVar
from analysis.callgraph import code_xrefs_tree_to

MAX_CHAIN_DEPTH = 20


@dataclass
class ChainNode:
    func_ea: int
    func_name: str


@dataclass
class IRCallFlowContext:
    nodes: list[ChainNode]


@dataclass(frozen=True)
class ChainBuildResult:
    context: IRCallFlowContext
    requested_stop_point: TraceDestination
    reached_stop_point: TraceDestination | None
    stop_message: str | None

# recursive base case. Iniitalize LLVMIRLifter here
def build_taint_slice(
    sink_ea: int,
    taint_vars: set[TaintedVar],
    entrypoints: list[int],
    facts_output_dir: Path | None = None,
) -> ChainBuildResult:
    sink_func_ea = ida_wrapper.func_start(sink_ea)
    output_dir = Path(facts_output_dir).parent if facts_output_dir else Path("findings")
    emitter = LLVMIREmitter(idb_path="", output_dir=output_dir)
    return build_next_node(
        sink_func_ea, None, taint_vars, set(), 0, entrypoints,
        callee_callsite_ea=sink_ea,
        facts_output_dir=facts_output_dir,
        emitter=emitter,
    )


# recursive case. emit constraints for the next node in the chain using LLVMIRLifter
def build_next_node(
    current_ea: int,
    chain_callee_ea: int | None,
    taint_vars: set[TaintedVar],
    visited: set[int],
    depth: int,
    entrypoints: list[int],
    callee_callsite_ea: int | None = None,
    facts_output_dir: Path | None = None,
    emitter: LLVMIREmitter | None = None,
) -> ChainBuildResult:
    _repr = next(iter(taint_vars), None)
    _trace_dest = _repr.trace_dest if _repr else TraceDestination.ENTRY_POINT

    if depth > MAX_CHAIN_DEPTH or current_ea in visited:
        logger.info("terminating trace func=0x%x reason=depth_or_cycle", current_ea)
        if emitter is not None:
            emitter.llvm_from_decompilation()
        return ChainBuildResult(
            IRCallFlowContext(nodes=[]),
            _trace_dest,
            None,
            "trace terminated before reaching a configured stop point",
        )

    visited.add(current_ea)

    logger.info(
        "set chain target for func=0x%x callee_ea=%s",
        current_ea,
        hex(chain_callee_ea) if chain_callee_ea is not None else "None",
    )
    if emitter is not None:
        emitter.add_decompilation(current_ea)
    node = ChainNode(
        func_ea=current_ea,
        func_name=ida_wrapper.name_from_address(current_ea),
    )
    next_taint_vars = set(taint_vars)
    
    # get list of (caller_func_ea, callsite_ea) pairs that call this function
    caller_callsite_pairs = code_xrefs_tree_to(
        [current_ea], max_depth=1, include_this_function=False
    )
    logger.info(
        "callers_of func=0x%x pairs=%s",
        current_ea,
        [(hex(f), hex(cs)) for f, cs in caller_callsite_pairs],
    )

    if not caller_callsite_pairs:
        if current_ea in entrypoints:
            logger.info(
                "trace stopped at entry point, stop location = %s",
                node.func_name
            )
            if emitter is not None:
                emitter.llvm_from_decompilation()
            return ChainBuildResult(
                IRCallFlowContext(nodes=[node]),
                _trace_dest,
                TraceDestination.ENTRY_POINT,
                f"Trace reached entry point {node.func_name}",
            )
        else:
            raise ValueError("WTF!!!")

    caller_func_ea, _callsite_ea = caller_callsite_pairs[0]
    logger.info("descending to caller next_ea=0x%x from func=0x%x", caller_func_ea, current_ea)

    suffix = build_next_node(
        caller_func_ea,
        current_ea,
        next_taint_vars if next_taint_vars else taint_vars,
        visited,
        depth + 1,
        entrypoints=entrypoints,
        callee_callsite_ea=_callsite_ea,
        facts_output_dir=facts_output_dir,
        emitter=emitter,
    )

    if not suffix.context.nodes:
        logger.info(
            "suffix chain empty func=0x%x propagating status requested_stop_point=%s",
            current_ea,
            suffix.requested_stop_point,
        )
        return ChainBuildResult(
            IRCallFlowContext(nodes=[node]),
            suffix.requested_stop_point,
            suffix.reached_stop_point,
            suffix.stop_message,
        )

    logger.info("assembled chain func=0x%x total_len=%d", current_ea, 1 + len(suffix.context.nodes))

    return ChainBuildResult(
        IRCallFlowContext(nodes=[node, *suffix.context.nodes]),
        suffix.requested_stop_point,
        suffix.reached_stop_point,
        suffix.stop_message,
    )

def _is_loop_site(call_site: tuple[dict[int, object], object, bool] | None) -> bool:
    result = bool(call_site and call_site[2])
    logger.info("is_loop_site=%s", result)
    return result


def _resolve_call_args(call_site: tuple[dict[int, object], object, bool] | None) -> dict[int, object]:
    result = {} if call_site is None else call_site[0]
    logger.info("resolve_call_args count=%d", len(result))
    return result
