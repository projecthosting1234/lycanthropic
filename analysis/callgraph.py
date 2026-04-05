"""Vtable call detection for C++ virtual function analysis.

Implements the algorithm:
1. Find function pointer xref in .rdata
2. Walk backwards 8 bytes at a time to find vtable start (look for lea reference)
3. Calculate offset from vtable start
4. Scan ALL EXECUTABLE SEGMENTS for mov rax, [rax + offset] pattern
5. Search forward for call instruction
6. Check if call is indirect (pointer or register)
7. Validate callsite by comparing function prototype arg count with callsite arg count
"""

from __future__ import annotations

import sys
import re
from collections import deque
from pathlib import Path
from typing import Any
from analysis.common import ida_wrapper
from analysis.common.debug import logger
from analysis.symbolic_object import Sink


def build_forward_reachable_set(
    entry_point_eas: list[int],
    max_depth: int = 17,
) -> set[int]:
    """Forward BFS from entry points, following callees (CodeRefsFrom).

    Returns a set of function start EAs reachable FROM the entry points.
    Used for Phase 2: keep call sites only if their containing function
    is reachable from some entry point.
    """
    import ida_funcs
    import idautils

    reachable: set[int] = set()
    queue: deque[tuple[int, int]] = deque()

    for ea in entry_point_eas:
        func = ida_funcs.get_func(ea)
        if func:
            start = func.start_ea
            if start not in reachable:
                reachable.add(start)
                queue.append((start, 0))

    while queue:
        func_ea, depth = queue.popleft()
        if depth >= max_depth:
            continue

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        # CodeRefsFrom: callees (functions this function calls)
        for head in idautils.Heads(func.start_ea, func.end_ea):
            import ida_bytes

            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                for ref in idautils.CodeRefsFrom(head, True):
                    callee_func = ida_funcs.get_func(ref)
                    if callee_func:
                        callee_start = callee_func.start_ea
                        if callee_start not in reachable:
                            reachable.add(callee_start)
                            queue.append((callee_start, depth + 1))

    return reachable



def _get_potential_vtable_xref(func_ea: int) -> list[int]:
    """Find all data xrefs to func_ea in .rdata section.

    Validates that the xref location contains an 8-byte pointer equal to func_ea.
    """
    import idautils
    import ida_segment
    import ida_bytes

    rdata = ida_wrapper._get_rdata_section()
    if not rdata:
        return []

    rdata_start, rdata_end = rdata
    xrefs = []

    for ref_ea in idautils.DataRefsTo(func_ea):
        if rdata_start <= ref_ea < rdata_end:
            # Check if ref_ea contains an 8-byte unsigned int equal to func_ea
            ptr_value = ida_bytes.get_qword(ref_ea)
            if ptr_value == func_ea:
                xrefs.append(ref_ea)

    return xrefs


def _count_args_in_prototype(prototype: str) -> int:
    """Count number of arguments in function prototype by counting commas."""
    # Remove everything after '{'
    if "{" in prototype:
        prototype = prototype[: prototype.index("{")]

    # Find content between parentheses
    match = re.search(r"\((.*)\)", prototype, re.DOTALL)
    if not match:
        return 0

    args_str = match.group(1).strip()
    if not args_str or args_str == "void":
        return 0

    # Count commas
    return args_str.count(",") + 1


def _count_args_in_decompiled_function(func_ea: int) -> tuple[int, str] | None:
    """Count function arguments by decompiling and counting commas in prototype.

    Args:
        func_ea: Address of the function

    Returns:
        Tuple of (arg_count, prototype_str) or None if failed
    """
    import ida_funcs

    # Get function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    # Decompile to get pseudocode with prototype
    pseudocode, _ = cached_decompile(func_ea)
    if not pseudocode or pseudocode.startswith("(decompilation failed"):
        return None

    # Extract prototype (first line until '{')
    prototype = _extract_prototype(pseudocode)
    if not prototype:
        return None

    # Count commas before ')' to get argument count
    # Find the params section between '(' and ')'
    match = re.search(r"\(([^)]*)\)", prototype)

    if not match:
        return (0, prototype)

    params_str = match.group(1).strip()
    # print("[*] Params string:", params_str)
    if not params_str or params_str == "void":
        return (0, prototype)

    # Count commas to determine arg count
    arg_count = params_str.count(",") + 1
    return (arg_count, prototype)


def _extract_callsite_prototype(
    target_func_ea: int, caller_ea: int, vtable_offset: int
) -> dict | None:
    """Extract and compare function prototype with callsite argument count.

    This validates whether a vtable call actually matches the target function
    by comparing the number of arguments in the function prototype vs the
    number of arguments passed at the callsite.

    Args:
        target_func_ea: Address of the target function (in vtable)
        caller_ea: Address of the caller function
        vtable_offset: Offset in vtable where function pointer is located

    Returns:
        Dict with validation results, or None if validation failed
        {
            "is_valid": bool,  # True if arg counts match within tolerance
            "func_arg_count": int,
            "callsite_arg_count": int,
            "prototype": str,
            "callsite_line": str,
        }
    """
    # Get target function argument count by decompiling and counting commas
    func_info = _count_args_in_decompiled_function(target_func_ea)
    if not func_info:
        return None

    func_arg_count, prototype = func_info

    # Decompile caller function to find callsite
    caller_pseudocode, _ = cached_decompile(caller_ea)
    if not caller_pseudocode or caller_pseudocode.startswith("(decompilation failed"):
        return None

    # Find the vtable call line using regex pattern
    # Vtable call format: *(<returntype> (<callconv>)(<params>, ...))
    # Example: (*(__int64 (__fastcall **)(CClfsLogFcbVirtual *))(*(_QWORD *)this + 112LL))(this);
    # Look for two consecutive parenthesis pairs: )(<params>) after a type pattern, after a *( asterisk and opening parenthesis
    # IGNORE lines that do not have the vtable_offset in them (in hex or decimal format)

    # Pattern to match vtable call: *(<type> (<callconv> **)(<params>))...
    # We look for: )(<params>) pattern - two parens next to each other
    # The params are inside the second pair of parens after the type

    # Convert vtable_offset to both hex and decimal strings for matching
    vtable_offset_hex = f"0x{vtable_offset:x}"
    vtable_offset_dec = str(vtable_offset)

    callsite_line = ""
    callsite_arg_count = 0

    # Search through each line of the caller pseudocode
    for line in caller_pseudocode.splitlines():
        line = line.strip()

        # Skip lines that don't contain the vtable offset
        if vtable_offset_hex not in line and vtable_offset_dec not in line:
            continue

        # Look for vtable call pattern: *(<type_name> (<callconv> **)(<params>))...
        # Pattern: *( followed by type name, then )(<params>) pattern
        # This ensures we're looking at a proper vtable function pointer call
        # Pattern: *(<anything>)(<params>)
        pattern = r"\*\([^)]+\)\s*\(([^)]+)\)"
        match = re.search(pattern, line)

        if match:
            callsite_line = line
            params_str = match.group(1).strip()

            # Count arguments in the callsite by counting commas
            if not params_str or params_str == "void":
                callsite_arg_count = 0
            else:
                callsite_arg_count = params_str.count(",") + 1
            break

    # If no vtable call line found, return None
    if not callsite_line:
        return None

    # Validate: if arg counts differ by more than 1, it's not a valid vtable call
    arg_diff = abs(func_arg_count - callsite_arg_count)
    is_valid = arg_diff <= 1

    return {
        "is_valid": is_valid,
        "func_arg_count": func_arg_count,
        "callsite_arg_count": callsite_arg_count,
        "prototype": prototype,
        "callsite_line": callsite_line,
    }


def _gather_all_vtable_callers(
    executable_segments: list[tuple[int, int]],
) -> list[dict]:
    """Gather ALL potential vtable callers from all executable segments.

    Scans all executable segments once and finds all patterns of:
    mov rax, [rax + offset] followed by indirect call (register, memory, or function pointer)

    Does NOT perform prototype validation - just gathers raw caller information.
    The results are cached globally to avoid re-scanning for every function.

    Args:
        executable_segments: List of (start, end) tuples for all executable segments

    Returns:
        List of dicts with caller info including vtable_offset:
        {
            "caller_ea": int,
            "caller_name": str,
            "vtable_load_ea": int,
            "vtable_offset": int,
            "call_ea": int,
            "call_type": str,
            "call_subtype": str,
            "args_passed_num": int | None,  # Populated later by _find_vtable_callers_for_offset
        }
    """
    import idautils
    import ida_funcs
    import ida_ua
    import idaapi

    all_callers = []
    seen_keys: set[tuple[int, int]] = set()  # (caller_ea, vtable_offset)

    for seg_start, seg_end in executable_segments:
        # Scan all instructions in this segment
        for head in idautils.Heads(seg_start, seg_end):
            # Decode instruction
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, head):
                continue

            # Check for mov rax, [rax + offset] pattern
            # This is a mov with memory operand using rax base + displacement
            if insn.itype == idaapi.NN_mov:
                # Check if it's mov reg, [mem]
                if (
                    insn.ops[0].type == ida_ua.o_reg
                    and insn.ops[1].type == ida_ua.o_displ
                ):
                    # Check base register is rax (reg 0 on x64)
                    if (
                        insn.ops[1].reg == 0 and insn.ops[0].reg == 0
                    ):  # rax base, rax dest
                        vtable_offset = insn.ops[1].addr

                        # Found pattern - now search forward for call
                        caller_info = _find_call_after_vtable_load(
                            head, seg_end, vtable_offset
                        )
                        if caller_info:
                            func = ida_funcs.get_func(head)
                            if func:
                                key = (func.start_ea, vtable_offset)
                                if key not in seen_keys:
                                    seen_keys.add(key)
                                    caller_data = {
                                        "caller_ea": func.start_ea,
                                        "caller_name": ida_funcs.get_func_name(
                                            func.start_ea
                                        )
                                        or f"sub_{func.start_ea:x}",
                                        "vtable_load_ea": head,
                                        "vtable_offset": vtable_offset,
                                        "call_ea": caller_info["call_ea"],
                                        "call_type": caller_info["call_type"],
                                        "call_subtype": caller_info.get(
                                            "call_subtype", "unknown"
                                        ),
                                        "args_passed_num": None,  # Will be populated by validation
                                    }
                                    all_callers.append(caller_data)

    return all_callers


def _find_vtable_callers_for_offset(
    vtable_offset: int, executable_segments: list[tuple[int, int]], target_func_ea: int
) -> list[dict]:
    """Find all functions that make vtable calls with given offset.

    Uses the global cache of gathered vtable callers. For each matching caller,
    performs prototype validation and caches the args_passed_num.

    Args:
        vtable_offset: The vtable offset to search for
        executable_segments: List of executable segment ranges (used for initial gather)
        target_func_ea: Address of the target function for prototype validation

    Returns:
        List of validated caller dicts with args_passed_num populated
    """
    import ida_funcs

    global _vtable_callers_cache

    # Initialize cache if not already populated
    if _vtable_callers_cache is None:
        _vtable_callers_cache = _gather_all_vtable_callers(executable_segments)

    matching_callers = []

    # Filter cached callers by vtable_offset
    for caller in _vtable_callers_cache:
        if caller["vtable_offset"] != vtable_offset:
            continue

        # Check if we already have cached args_passed_num for this caller
        if caller.get("args_passed_num") is None:
            # Need to validate and extract args_passed_num
            validation = _extract_callsite_prototype(
                target_func_ea, caller["caller_ea"], vtable_offset
            )
            if validation:
                # Cache the args_passed_num for future calls
                caller["args_passed_num"] = validation.get("callsite_arg_count", 0)

                # Only include if validation passes
                if validation.get("is_valid", True):
                    # Add validation info to a copy of the caller data
                    caller_copy = dict(caller)
                    caller_copy["validation"] = validation
                    matching_callers.append(caller_copy)
            else:
                # No validation available, skip this caller
                continue
        else:

            # Already have cached args_passed_num, just need to validate target func
            # Get target function arg count (not cached, computed each time)
            func_info = _count_args_in_decompiled_function(target_func_ea)

            if func_info:
                func_arg_count, _ = func_info
                arg_diff = abs(func_arg_count - caller["args_passed_num"])
                is_valid = arg_diff <= 1

                if is_valid:
                    # Create validation dict for consistency
                    validation = {
                        "is_valid": True,
                        "func_arg_count": func_arg_count,
                        "callsite_arg_count": caller["args_passed_num"],
                        "prototype": "",
                        "callsite_line": "",
                    }
                    caller_copy = dict(caller)
                    caller_copy["validation"] = validation
                    matching_callers.append(caller_copy)

    return matching_callers


def _find_call_after_vtable_load(
    vtable_load_ea: int, seg_end: int, vtable_offset: int
) -> dict | None:
    """Search forward from vtable load for indirect call instruction.

    Handles various indirect call patterns:
    - call reg (e.g., call rax)
    - call [reg] (e.g., call [rax])
    - call [reg+off] (e.g., call [rax+0x10])
    - call ptr (e.g., call cs:__guard_dispatch_icall_fptr)
    """
    import ida_bytes
    import ida_ua
    import ida_idaapi
    import idaapi

    max_search = 50  # Max instructions to search
    curr = vtable_load_ea
    count = 0

    while curr < seg_end and count < max_search:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, curr):
            curr = ida_bytes.next_head(curr, seg_end)
            count += 1
            continue

        # Check for call instruction
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            # Check if it's an indirect call (call register, call [mem], or call ptr)
            is_indirect = False
            call_subtype = "unknown"

            if insn.ops[0].type == ida_ua.o_reg:  # call reg (e.g., call rax)
                is_indirect = True
                call_subtype = "register"
            elif insn.ops[0].type == ida_ua.o_phrase:  # call [reg] (e.g., call [rax])
                is_indirect = True
                call_subtype = "memory_indirect"
            elif (
                insn.ops[0].type == ida_ua.o_displ
            ):  # call [reg+off] (e.g., call [rax+0x10])
                is_indirect = True
                call_subtype = "displacement"
            elif (
                insn.ops[0].type == ida_ua.o_mem
            ):  # call ptr (e.g., call cs:__guard_dispatch_icall_fptr)
                # This handles Control Flow Guard (CFG) calls through global function pointers
                is_indirect = True
                call_subtype = "function_pointer"

            if is_indirect:
                return {
                    "call_ea": curr,
                    "call_type": "indirect",
                    "call_subtype": call_subtype,
                    "is_virtual": True,
                }

            # Direct call - not a vtable call
            return None

        # Stop if we hit a ret or unconditional jmp
        if insn.itype in (idaapi.NN_retn, idaapi.NN_jmp):
            return None

        curr = ida_bytes.next_head(curr, seg_end)
        count += 1

    return None


def find_vtable_callers(func_ea: int) -> list[tuple[int, int]]:
    """Find all functions that call func_ea through a vtable.

    Main entry point for vtable caller detection.

    Returns a list of (caller_func_start_ea, callsite_ea) pairs.
    """
    import ida_funcs

    # Validate function
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    # Get function start
    func_start = func.start_ea

    # Find all xrefs to this function in .rdata
    rdata_xrefs = _get_potential_vtable_xref(func_start)
    if not rdata_xrefs:
        return []

    # Get ALL executable segments (not just .text)
    executable_segments = _get_executable_segments()
    if not executable_segments:
        return []

    pairs: set[tuple[int, int]] = set()

    for xref_ea in rdata_xrefs:
        # Find vtable start and offset
        vtable_info = get_vtable(xref_ea)
        if not vtable_info:
            continue

        _, offset = vtable_info

        # Find callers for this offset across ALL executable segments
        # Pass target_func_ea for prototype validation
        callers = _find_vtable_callers_for_offset(
            offset, executable_segments, func_start
        )

        for caller in callers:
            caller_ea = caller.get("caller_ea")
            call_ea = caller.get("call_ea")
            if isinstance(caller_ea, int) and isinstance(call_ea, int):
                pairs.add((caller_ea, call_ea))

    return list(pairs)


def code_xrefs_tree_to(
    code_address: list[int] | set[int],
    max_depth: int = 17,
    include_this_function: bool = True,
    only_branches: bool = False,
) -> list[tuple[int, int]]:
    """Backward BFS in call graph from a set of addresses, following code refs (callers), data refs, and vtable calls.

    Returns a list of (caller_func_start_ea, callsite_ea) pairs. Each pair means the function at
    caller_func_start_ea contains a call at callsite_ea that reaches (eventually) the seed addresses.
    Pass max_depth=1 for only direct callers. Pass include_this_function=False to exclude the seed
    functions (use when you want "who calls this?" and not "who can reach this?").
    """
    import ida_funcs
    import idautils

    # Seed: functions containing the given addresses (callsites)
    frontier: set[int] = set()
    reachable_funcs: set[int] = set()
    pairs: list[tuple[int, int]] = []

    for address in code_address:
        func = ida_funcs.get_func(address)
        if func:
            frontier.add(func.start_ea)
            reachable_funcs.add(func.start_ea)
            pairs.append((func.start_ea, address))
    depth = 0

    while frontier and depth < max_depth:
        next_frontier: set[int] = set()

        for func_start in frontier:
            # CodeRefsTo: direct calls to this function
            for ref in idautils.CodeRefsTo(func_start, True):
                logger.info(
                    "code_xrefs_tree_to CodeRefsTo ref=0x%x func_start=0x%x",
                    ref,
                    func_start,
                )
                caller_func = ida_funcs.get_func(ref)
                if caller_func:
                    caller_start = caller_func.start_ea
                    pairs.append((caller_start, ref))
                    if caller_start not in reachable_funcs:
                        next_frontier.add(caller_start)
                        reachable_funcs.add(caller_start)

            # Vtable calls: functions that call this function via vtable
            for caller_ea, call_site_ea in find_vtable_callers(func_start):
                pairs.append((caller_ea, call_site_ea))
                if caller_ea not in reachable_funcs:
                    next_frontier.add(caller_ea)
                    reachable_funcs.add(caller_ea)

        frontier = next_frontier
        depth += 1

    if not include_this_function:
        seed_funcs = {
            ida_funcs.get_func(addr).start_ea
            for addr in code_address
            if ida_funcs.get_func(addr)
        }
        pairs = [(f, cs) for f, cs in pairs if f not in seed_funcs]

    return pairs


# ── Entry Point Discovery ───────────────────────────────────────


def find_entry_points(FUNCTION_NO_XREFS_LAZY_CANDIDATE=True) -> list[dict]:
    """Find driver entry points (DriverEntry and variants).

    Returns list of dicts: [{name, ea, kind}].
    Falls back to the binary's PE entry point if no name match is found.
    """
    import ida_funcs
    import ida_ida
    import idautils

    results = []
    seen_names: set[str] = set()  # Track unique function names

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        name = ida_funcs.get_func_name(ea)
        if not name:
            continue

        if FUNCTION_NO_XREFS_LAZY_CANDIDATE:
            # Fine-grained check: only consider as entry point if:
            # 1. No code references (callers)
            # 2. No data references in .rdata section (vtable)
            has_callers = False
            for _ in idautils.CodeRefsTo(ea, True):
                has_callers = True
                break

            has_rdata_refs = False
            import ida_segment

            rdata_seg = ida_segment.get_segm_by_name(".rdata")
            # rdata_ref = []

            for ref in idautils.DataRefsTo(ea):
                if rdata_seg and rdata_seg.start_ea <= ref < rdata_seg.end_ea:
                    has_rdata_refs = True
                    break

            if not has_callers and not has_rdata_refs:
                if name not in seen_names:
                    seen_names.add(name)
                    results.append({"name": name, "ea": ea, "kind": "no_xrefs"})

    if results:
        logger.info(
            f"[*] Reachability: found {len(results)} entry point(s) by name: "
            f"{', '.join(r['name'] for r in results)}"
        )

    # Pass 2: fallback to PE entry point

    start_ea = ida_ida.inf_get_start_ea()
    if start_ea and start_ea != 0xFFFFFFFFFFFFFFFF:
        func = ida_funcs.get_func(start_ea)
        if func:
            name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            if name not in seen_names:
                seen_names.add(name)
                results.append({"name": name, "ea": func.start_ea, "kind": "pe_entry"})
                logger.info(
                    f"[*] Reachability: using PE entry point: {name} @ 0x{func.start_ea:x}"
                )
        else:
            logger.info(
                f"[*] Reachability: PE entry 0x{start_ea:x} is not inside a function"
            )

    return results


# ── Two-Phase Entry Point and Sink Filtering ────────────────────


def prune_unreachable_entries_then_callsites(
    callsites: list[int],
    sink: Sink,
    max_depth: int = 15,
) -> tuple[list[int], list[int]]:
    """Two-phase pruning: first filter entry points, then filter sinks.

    Phase 1: Build backward reachable set from all sink call sites.
             Filter entry points to keep only those reachable from sinks.
    Phase 2: Filter sinks to keep only those that reach at least one
             valid entry point.

    This ensures we don't waste effort on:
    - Entry points that no sink can reach (orphaned code paths)
    - Sinks that can't reach any valid entry point (dead code)
    
    returns reachable sink callsites and reachable entry points

    Args:
        sink_list:  SinkList from step 1 (sink identification).
        max_depth:  Maximum BFS depth for reachability (default 15).
    """
    import ida_funcs

    # Step 1: find all entry points
    entry_points = find_entry_points(FUNCTION_NO_XREFS_LAZY_CANDIDATE=True)
    if not entry_points:
        logger.info("[*] Reachability: no entry points found, skipping pruning")
        return callsites, []

    # Step 3: backward BFS from sink call sites to find what can reach them

    sink_caller_pairs = code_xrefs_tree_to(callsites, max_depth=max_depth)
    reachable_from_sinks = list({p[0] for p in sink_caller_pairs})

    # Step 4: PHASE 1 - Filter entry points to those reachable from sinks
    reachable_entry_points = [
        ep for ep in entry_points if ep["ea"] in reachable_from_sinks
    ]

    reachable_names = [
        ep["name"] for ep in entry_points if ep["ea"] in reachable_from_sinks
    ]
    logger.info(
        f"[*] Filter 1: {len(entry_points)} -> {len(reachable_entry_points)} entry points "
        f"{' '.join(reachable_names)}"
    )
        
    # If no entry points are reachable, return empty sink list
    if not reachable_entry_points:
        logger.info(
            "[*] Reachability: no entry points reachable from any sink, returning empty"
        )
        return [], []

    # Step 5: PHASE 2 - Filter call sites to those reachable from at least one valid entry point
    # Forward BFS from entry points: which functions can we reach?
    entry_eas = [ep["ea"] for ep in reachable_entry_points]
    forward_reachable = build_forward_reachable_set(entry_eas, max_depth=max_depth)
    logger.info(
        f"[*] Reachability: {len(forward_reachable)} functions reachable from entry points"
    )

    kept_callsites: list[int] = []
    for cs in callsites:
        func = ida_funcs.get_func(cs)
        if not func:
            continue
        if func.start_ea in forward_reachable:
            kept_callsites.append(cs)

    pruned_callsite_count = len(callsites) - len(kept_callsites)
    logger.info(
        f"[*] Filter 2: {len(callsites)} -> {len(kept_callsites)} call sites "
        f"({pruned_callsite_count} pruned)"
    )

    return kept_callsites, entry_eas
