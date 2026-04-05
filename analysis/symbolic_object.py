from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any

from analysis.common.debug import logger
from analysis.common import ida_wrapper
from ida_hexrays import cfuncptr_t
import ida_typeinf

Expr = Any
Constraint = Any
SourceInfo = Any
IRFunctionNode = Any

class TraceDestination(Enum):
    ENTRY_POINT = auto()
    ALLOCATION_SITE = auto()
    USER_INPUT_FUNC = auto()


class VariableResultStatus(Enum):
    SAT = auto()
    UNSAT = auto()
    INCONCLUSIVE = auto()


@dataclass
class TaintedVar:
    name: str
    param_index: int
    bitwidth: int
    trace_dest: TraceDestination
    taint_boundary_name: str
    tags: tuple[str, ...] = ()
    description: str = ""
    sink_tags: tuple[str, ...] = ()
    initial_expr: Expr | None = None
    
    def __str__(self):
        return self.name

    def __hash__(self) -> int:
        result = hash(self.name)
        return result

    def __eq__(self, other: object) -> bool:
        result = isinstance(other, TaintedVar) and self.name == other.name
        return result



@dataclass(frozen=True)
class ChainEdge:
    caller_ea: int
    callee_ea: int
    call_site_ref: SourceInfo
    loop_carried: bool
    loop_bound_expr: Expr | None = None


@dataclass
class Callsite:
    """One call site: return expr, callee node (or placeholder/None until refined), and callsite address."""
    ret_expr: Expr
    callee: IRFunctionNode | None
    callsite_ea: int
    callee_ea: int = 0  # func_ea of callee when callee is None (e.g. chain target)


@dataclass
class VariableResult:
    variables: tuple[TaintedVar, ...]  # taint set this result applies to
    call_tree: IRFunctionNode | None
    is_sat: bool
    sat_model: dict[str, int] | None
    sexpr: str
    refinement_rounds: int
    status: VariableResultStatus = VariableResultStatus.UNSAT
    requested_stop_point: TraceDestination | None = None
    reached_stop_point: TraceDestination | None = None
    stop_message: str | None = None

    @property
    def variable(self) -> TaintedVar:
        """Backward compat: first variable when treated as single-var result."""
        return self.variables[0]

    def to_json(self) -> dict[str, Any]:
        """Serialize this VariableResult (and nested structures) to a JSONable dict."""

        def _expr_to_json(expr: Expr | None) -> dict[str, Any] | None:
            if expr is None:
                return None
            return {
                "op": expr.op.name,
                "args": [_expr_to_json(arg) for arg in expr.args],
                "literal": expr.literal,
                "symbol": expr.symbol,
                "bitwidth": expr.bitwidth,
                "ref": _source_ref_to_json(expr.ref),
            }

        def _source_ref_to_json(ref: SourceInfo | None) -> dict[str, Any] | None:
            if ref is None:
                return None
            return asdict(ref)

        def _constraint_to_json(item: Constraint) -> dict[str, Any]:
            result: dict[str, Any] = {
                "kind": item.kind.name,
                "expr": _expr_to_json(item.expr),
                "node_ea": item.parent_block_ea,
                "ref": _source_ref_to_json(item.ref),
                "tainted_vars": list(getattr(item, "tainted_vars", ())),
            }
            if getattr(item, "block_ea", None) is not None:
                result["block_ea"] = item.then_block_ea
            if getattr(item, "else_block_ea", None) is not None:
                result["else_block_ea"] = item.else_block_ea
            return result

        def _ir_node_to_json(node: IRFunctionNode) -> dict[str, Any]:
            return {
                "func_ea": node.func_ea,
                "func_name": node.func_name,
                "is_chain_node": node.is_chain_node,
                "constraints": [_constraint_to_json(item) for item in node.constraints],
                "call_args": {str(key): _expr_to_json(value) for key, value in node.call_args.items()},
                "return_summary": _expr_to_json(node.return_summary),
                "callee_sites": [{"ret_expr": _expr_to_json(s.ret_expr), "callee": _ir_node_to_json(s.callee) if s.callee else None, "callsite_ea": s.callsite_ea, "callee_ea": s.callee_ea} for s in node.callee_sites],
                "ref": _source_ref_to_json(node.ref),
            }

        def _variable_to_json(item: TaintedVar) -> dict[str, Any]:
            return {
                "name": item.name,
                "param_index": item.param_index,
                "bitwidth": item.bitwidth,
                "trace_dest": item.trace_dest.name,
                "sink_name": item.taint_boundary_name,
                "tags": list(item.tags),
                "description": item.description,
                "sink_tags": list(item.sink_tags),
                "initial_expr": _expr_to_json(item.initial_expr),
            }

        return {
            "variables": [_variable_to_json(v) for v in self.variables],
            "call_tree": _ir_node_to_json(self.call_tree) if self.call_tree is not None else None,
            "is_sat": self.is_sat,
            "sat_model": self.sat_model,
            "sexpr": self.sexpr,
            "refinement_rounds": self.refinement_rounds,
            "status": self.status.name,
            "requested_stop_point": self.requested_stop_point.name if self.requested_stop_point is not None else None,
            "reached_stop_point": self.reached_stop_point.name if self.reached_stop_point is not None else None,
            "stop_message": self.stop_message,
        }

@dataclass
class Sink:
    label: str
    tags: tuple[str, ...] = ()
    initial_callers: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    asm: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    parameters: list[TaintedVar] = field(default_factory=list)

    def get_param_by_tag(
        self,
        required_tags: set[str],
    ) -> set[TaintedVar]:

        result = {
            variable
            for variable in self.parameters
            if variable.taint_boundary_name == self.label
            and required_tags.issubset(set(variable.tags))
        }
        return result

    def get_param_list(self) -> list[TaintedVar]:
        return self.parameters


    def gather_initial_callsites(self) -> list[int]:
        seen: set[int] = set()
        callsites: list[int] = []

        if len(self.initial_callers) > 0:

            all_names = []

            for imported in self.imports:
                all_names.append(imported.lower())
            for asm in self.asm:
                all_names.append(asm.lower())
            for f in self.functions:
                all_names.append(f.lower())

            for item in self.initial_callers:
                initial_callsite_ea = int(item, 16)
                line = ida_wrapper.get_disasm_line(initial_callsite_ea)

                found = False
                for n in all_names:
                    if n in line.lower():
                        found = True

                if found == False:
                    raise ValueError(f"Sink {self.label} not invoked at {item} !! Fix or remove this initial caller address in config.json")
                
                seen.add(int(item, 16))
                callsites.append(int(item, 16))
            
                

            return callsites

        for imported in self.imports:
            for entry in ida_wrapper._get_all_imports():
                if imported.lower() not in entry["name"].lower():
                    continue

                for ref in ida_wrapper._branch_xrefs_to(entry["ea"]):
                    addr = int(ref["addr"], 16)
                    if addr not in seen:
                        seen.add(addr)
                        callsites.append(addr)

        for text in self.asm:
            for hit in ida_wrapper._search_asm(text):
                addr = int(hit["addr"], 16)
                if addr not in seen:
                    seen.add(addr)
                    callsites.append(addr)

        for pattern in self.functions:
            if not pattern:
                continue

            for func in ida_wrapper._search_functions_by_name(pattern):
                for ref in ida_wrapper._branch_xrefs_to(func["ea"]):
                    addr = int(ref["addr"], 16)
                    if addr not in seen:
                        seen.add(addr)
                        callsites.append(addr)

        result = sorted(callsites)

        return result

class FunctionType(Enum):
    UNKNOWN = auto()
    CHAIN = auto()
    NONCHAIN = auto()
    API = auto()
    INTRINSIC = auto()

class Callsite:
    callsite_ea: int
    callee_ea: int
    callee_name: str
    callee_ref: FunctionInfo | None = None

    def __init__(self, callsite_ea: int, callee_ea: int, callee_name: str):
        self.callsite_ea = callsite_ea
        self.callee_ea = callee_ea
        self.callee_name = callee_name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Callsite):
            return NotImplemented
        return self.callsite_ea == other.callsite_ea and self.callee_ea == other.callee_ea and self.callee_name == other.callee_name

    def __hash__(self) -> int:
        return hash(self.callsite_ea, self.callee_ea, self.callee_name)

class FunctionInfo:
    func_ea: int
    func_name: str
    callsites: list[Callsite]
    callees: list[Callsite]
    pseudocode: str
    ida_cfunc: cfuncptr_t | None
    ida_typeinfo: ida_typeinf.tinfo_t | None
    function_type: FunctionType

    def __init__(self, func_ea: int, func_name: str, function_type: FunctionType = FunctionType.UNKNOWN, call_type: ida_typeinf.tinfo_t = None):
        self.func_ea = func_ea
        self.func_name = func_name
        self.callsites = list()
        self.pseudocode = ""
        self.ida_cfunc = None
        self.function_type = function_type
        self.ida_typeinfo = call_type

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FunctionInfo):
            return NotImplemented
        return self.func_name == other.func_name

    def __hash__(self) -> int:
        return hash(self.func_name)