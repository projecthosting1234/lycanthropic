"""Sync and async wrappers for IDA's idalib API.

The IDA library is single-threaded: all calls must happen on the same thread
that performed `import idapro`. We use ThreadPoolExecutor(max_workers=1) to
guarantee this, identical to the windbg_mcp/dbgeng/async_client.py pattern.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from .config import Config

logger = logging.getLogger(__name__)


class IDAClient:
    """Synchronous IDA client — all methods run on the idalib thread."""

    def __init__(self):
        self._idapro = None
        self._db_open = False
        self._has_hexrays = False
        self._version = None

    def initialize(self) -> str:
        """Import idapro (which calls init_library) and return version string.

        MUST be called on the executor thread — idalib binds to the calling thread.
        """
        import idapro
        self._idapro = idapro
        idapro.enable_console_messages(False)

        ver = idapro.get_library_version()
        if ver:
            self._version = f"{ver[0]}.{ver[1]}.{ver[2]}"
        else:
            self._version = "unknown"

        logger.info("idalib initialized, version %s", self._version)
        return self._version

    @property
    def version(self) -> str:
        return self._version or "not initialized"

    @property
    def is_db_open(self) -> bool:
        return self._db_open

    @property
    def has_hexrays(self) -> bool:
        return self._has_hexrays

    def open_database(self, file_path: str, auto_analysis: bool = True) -> dict:
        """Open a binary file for analysis. Returns db info dict."""
        if self._db_open:
            raise RuntimeError("A database is already open. Close it first.")

        rc = self._idapro.open_database(file_path, auto_analysis)
        if rc != 0:
            raise RuntimeError(f"open_database failed with code {rc}")

        self._db_open = True

        # Wait for auto-analysis to complete if requested
        if auto_analysis:
            import ida_auto
            ida_auto.auto_wait()

        # Detect Hex-Rays decompiler
        self._has_hexrays = False
        try:
            import ida_hexrays
            if ida_hexrays.init_hexrays_plugin():
                self._has_hexrays = True
        except Exception:
            pass

        return self._get_db_info()

    def close_database(self, save: bool = True) -> None:
        """Close the current database."""
        if not self._db_open:
            return
        self._idapro.close_database(save)
        self._db_open = False
        self._has_hexrays = False

    def _get_db_info(self) -> dict:
        """Collect metadata about the currently open database."""
        import ida_ida
        import ida_nalt
        import ida_funcs

        if ida_ida.inf_is_64bit():
            bitness = 64
        elif ida_ida.inf_is_32bit_exactly():
            bitness = 32
        else:
            bitness = 16

        return {
            "file_path": ida_nalt.get_input_file_path(),
            "file_name": ida_nalt.get_root_filename(),
            "processor": ida_ida.inf_get_procname(),
            "bitness": bitness,
            "file_type": ida_ida.inf_get_filetype(),
            "entry_point": f"0x{ida_ida.inf_get_start_ea():x}",
            "function_count": ida_funcs.get_func_qty(),
            "has_hexrays": self._has_hexrays,
            "idalib_version": self._version,
        }

    # ── Core analysis methods ─────────────────────────────────────────

    def list_functions(self, name_filter: str = "", limit: int = 500) -> dict:
        import idautils
        import ida_funcs
        import ida_name

        results = []
        total = 0
        name_filter_lower = name_filter.lower()

        for ea in idautils.Functions():
            fname = ida_funcs.get_func_name(ea)
            if name_filter_lower and name_filter_lower not in fname.lower():
                continue
            total += 1
            if len(results) < limit:
                func = ida_funcs.get_func(ea)
                results.append({
                    "name": fname,
                    "start_ea": f"0x{ea:x}",
                    "size": func.size() if func else 0,
                })

        return {"functions": results, "total": total, "truncated": total > limit}

    def get_function_info(self, ea: int) -> dict:
        import ida_funcs
        import ida_name

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")

        return {
            "name": ida_funcs.get_func_name(ea),
            "start_ea": f"0x{func.start_ea:x}",
            "end_ea": f"0x{func.end_ea:x}",
            "size": func.size(),
            "flags": func.flags,
            "frame_size": func.frsize,
        }

    def disassemble(self, ea: int, count: int = 30) -> list[dict]:
        import ida_lines
        import ida_ua
        import ida_bytes

        results = []
        current = ea
        for _ in range(count):
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, current)
            if length == 0:
                break

            raw_bytes = ida_bytes.get_bytes(current, length)
            disasm = ida_lines.generate_disasm_line(current, 0)
            # Strip IDA color codes
            disasm = ida_lines.tag_remove(disasm)

            results.append({
                "ea": f"0x{current:x}",
                "bytes": raw_bytes.hex() if raw_bytes else "",
                "disasm": disasm,
                "size": length,
            })
            current += length

        return results

    def decompile(self, ea: int) -> str:
        if not self._has_hexrays:
            raise RuntimeError("Hex-Rays decompiler not available. Use disassemble instead.")

        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            raise RuntimeError(f"Decompilation failed for 0x{ea:x}")
        return str(cfunc)

    # ── Cross-references ──────────────────────────────────────────────

    def xrefs_to(self, ea: int, limit: int = 200) -> dict:
        import idautils
        import ida_funcs

        results = []
        total = 0
        for xref in idautils.XrefsTo(ea):
            total += 1
            if len(results) < limit:
                func = ida_funcs.get_func(xref.frm)
                results.append({
                    "from_ea": f"0x{xref.frm:x}",
                    "from_name": ida_funcs.get_func_name(xref.frm) if func else "",
                    "type": xref.type,
                })

        return {"xrefs": results, "total": total, "truncated": total > limit}

    def xrefs_from(self, ea: int, limit: int = 200) -> dict:
        import idautils
        import ida_funcs
        import ida_name

        results = []
        total = 0
        for xref in idautils.XrefsFrom(ea):
            total += 1
            if len(results) < limit:
                name = ida_name.get_name(xref.to)
                results.append({
                    "to_ea": f"0x{xref.to:x}",
                    "to_name": name or "",
                    "type": xref.type,
                })

        return {"xrefs": results, "total": total, "truncated": total > limit}

    def find_callers(self, ea: int, limit: int = 200) -> dict:
        import idautils
        import ida_funcs

        results = []
        total = 0
        for ref in idautils.CodeRefsTo(ea, True):
            total += 1
            if len(results) < limit:
                func = ida_funcs.get_func(ref)
                results.append({
                    "caller_ea": f"0x{ref:x}",
                    "caller_name": ida_funcs.get_func_name(ref) if func else "",
                })

        return {"callers": results, "total": total, "truncated": total > limit}

    # ── CFG / Graph ───────────────────────────────────────────────────

    def get_basic_blocks(self, ea: int) -> dict:
        import ida_gdl
        import ida_funcs
        import ida_ua
        import ida_lines

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")

        fc = ida_gdl.FlowChart(func)
        blocks = []
        edges = []
        block_map = {}

        for idx, bb in enumerate(fc):
            block_map[bb.id] = idx

            # Disassemble instructions in this block
            instructions = []
            current = bb.start_ea
            while current < bb.end_ea:
                insn = ida_ua.insn_t()
                length = ida_ua.decode_insn(insn, current)
                if length == 0:
                    break
                disasm = ida_lines.tag_remove(
                    ida_lines.generate_disasm_line(current, 0)
                )
                instructions.append({
                    "ea": f"0x{current:x}",
                    "disasm": disasm,
                })
                current += length

            succs = [s.id for s in bb.succs()]
            preds = [p.id for p in bb.preds()]

            blocks.append({
                "id": bb.id,
                "start_ea": f"0x{bb.start_ea:x}",
                "end_ea": f"0x{bb.end_ea:x}",
                "type": bb.type,
                "succs": succs,
                "preds": preds,
                "instructions": instructions,
            })

            for s in bb.succs():
                edges.append({"from_id": bb.id, "to_id": s.id})

        return {
            "func_name": ida_funcs.get_func_name(func.start_ea),
            "blocks": blocks,
            "edges": edges,
            "block_count": len(blocks),
            "edge_count": len(edges),
        }

    def get_call_graph(self, ea: int, depth: int = 2, direction: str = "both") -> dict:
        import idautils
        import ida_funcs
        import ida_name

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")

        nodes = {}
        edge_list = []
        root_ea = func.start_ea
        root_name = ida_funcs.get_func_name(root_ea)
        nodes[root_ea] = root_name

        # BFS
        queue = [(root_ea, 0)]
        visited = {root_ea}

        while queue:
            current_ea, current_depth = queue.pop(0)
            if current_depth >= depth:
                continue

            # Callees (forward)
            if direction in ("both", "callees"):
                current_func = ida_funcs.get_func(current_ea)
                if current_func:
                    for ref in idautils.CodeRefsFrom(current_func.start_ea, True):
                        pass
                    # Walk all instructions in function for call references
                    for head in idautils.Heads(current_func.start_ea, current_func.end_ea):
                        for ref in idautils.CodeRefsFrom(head, False):
                            target_func = ida_funcs.get_func(ref)
                            if target_func and target_func.start_ea != current_ea:
                                target_ea = target_func.start_ea
                                target_name = ida_funcs.get_func_name(target_ea)
                                nodes[target_ea] = target_name
                                edge_list.append({
                                    "from": f"0x{current_ea:x}",
                                    "to": f"0x{target_ea:x}",
                                })
                                if target_ea not in visited:
                                    visited.add(target_ea)
                                    queue.append((target_ea, current_depth + 1))

            # Callers (backward)
            if direction in ("both", "callers"):
                for ref in idautils.CodeRefsTo(current_ea, True):
                    caller_func = ida_funcs.get_func(ref)
                    if caller_func and caller_func.start_ea != current_ea:
                        caller_ea = caller_func.start_ea
                        caller_name = ida_funcs.get_func_name(caller_ea)
                        nodes[caller_ea] = caller_name
                        edge_list.append({
                            "from": f"0x{caller_ea:x}",
                            "to": f"0x{current_ea:x}",
                        })
                        if caller_ea not in visited:
                            visited.add(caller_ea)
                            queue.append((caller_ea, current_depth + 1))

        node_list = [{"ea": f"0x{ea:x}", "name": name} for ea, name in nodes.items()]
        return {
            "root": f"0x{root_ea:x}",
            "root_name": root_name,
            "nodes": node_list,
            "edges": edge_list,
        }

    def get_block_disasm(self, ea: int, block_id: int) -> dict:
        import ida_gdl
        import ida_funcs
        import ida_ua
        import ida_lines
        import ida_bytes

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")

        fc = ida_gdl.FlowChart(func)
        for bb in fc:
            if bb.id == block_id:
                instructions = []
                current = bb.start_ea
                while current < bb.end_ea:
                    insn = ida_ua.insn_t()
                    length = ida_ua.decode_insn(insn, current)
                    if length == 0:
                        break
                    disasm = ida_lines.tag_remove(
                        ida_lines.generate_disasm_line(current, 0)
                    )
                    raw_bytes = ida_bytes.get_bytes(current, length)
                    instructions.append({
                        "ea": f"0x{current:x}",
                        "bytes": raw_bytes.hex() if raw_bytes else "",
                        "disasm": disasm,
                        "size": length,
                    })
                    current += length
                return {
                    "block_id": block_id,
                    "start_ea": f"0x{bb.start_ea:x}",
                    "end_ea": f"0x{bb.end_ea:x}",
                    "instructions": instructions,
                }

        raise ValueError(f"Block {block_id} not found in function at 0x{ea:x}")

    def get_function_cfg_summary(self, ea: int) -> dict:
        import ida_gdl
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")

        fc = ida_gdl.FlowChart(func)
        block_count = 0
        edge_count = 0
        entry_blocks = []
        exit_blocks = []
        all_succs = set()

        for bb in fc:
            block_count += 1
            succs = list(bb.succs())
            preds = list(bb.preds())
            edge_count += len(succs)

            if not preds:
                entry_blocks.append(f"0x{bb.start_ea:x}")
            if not succs:
                exit_blocks.append(f"0x{bb.start_ea:x}")

            for s in succs:
                all_succs.add((bb.id, s.id))

        # Cyclomatic complexity: M = E - N + 2
        cyclomatic = edge_count - block_count + 2

        # Detect loops: a back edge exists if a successor has already been
        # visited in a DFS. Simpler: check if any edge target dominates its source.
        # Quick heuristic: any edge where to_id <= from_id suggests a loop.
        has_loops = any(to_id <= from_id for from_id, to_id in all_succs)

        return {
            "func_name": ida_funcs.get_func_name(func.start_ea),
            "block_count": block_count,
            "edge_count": edge_count,
            "cyclomatic_complexity": cyclomatic,
            "has_loops": has_loops,
            "entry_blocks": entry_blocks,
            "exit_blocks": exit_blocks,
        }

    # ── Enumeration ───────────────────────────────────────────────────

    def list_strings(self, min_length: int = 5, filter_str: str = "", limit: int = 500) -> dict:
        import idautils

        results = []
        total = 0
        filter_lower = filter_str.lower()

        for s in idautils.Strings():
            if s.length < min_length:
                continue
            value = str(s)
            if filter_lower and filter_lower not in value.lower():
                continue
            total += 1
            if len(results) < limit:
                results.append({
                    "ea": f"0x{s.ea:x}",
                    "value": value,
                    "length": s.length,
                    "type": s.strtype,
                })

        return {"strings": results, "total": total, "truncated": total > limit}

    def list_imports(self, module_filter: str = "", limit: int = 1000) -> dict:
        import ida_nalt

        modules = []
        total_imports = 0
        module_filter_lower = module_filter.lower()

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            mod_name = ida_nalt.get_import_module_name(i)
            if module_filter_lower and module_filter_lower not in mod_name.lower():
                continue

            imports = []

            def imp_cb(ea, name, ordinal):
                nonlocal total_imports
                total_imports += 1
                if total_imports <= limit:
                    imports.append({
                        "ea": f"0x{ea:x}",
                        "name": name or "",
                        "ordinal": ordinal,
                    })
                return True

            ida_nalt.enum_import_names(i, imp_cb)
            if imports:
                modules.append({"module": mod_name, "imports": imports})

        return {"modules": modules, "total_imports": total_imports, "truncated": total_imports > limit}

    def list_exports(self, name_filter: str = "", limit: int = 1000) -> dict:
        import idautils

        results = []
        total = 0
        name_filter_lower = name_filter.lower()

        for idx, ordinal, ea, name in idautils.Entries():
            if name_filter_lower and name_filter_lower not in (name or "").lower():
                continue
            total += 1
            if len(results) < limit:
                results.append({
                    "ordinal": ordinal,
                    "ea": f"0x{ea:x}",
                    "name": name or "",
                })

        return {"exports": results, "total": total, "truncated": total > limit}

    def list_segments(self) -> list[dict]:
        import ida_segment

        results = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            perm_str = ""
            if seg.perm & 4:
                perm_str += "R"
            if seg.perm & 2:
                perm_str += "W"
            if seg.perm & 1:
                perm_str += "X"

            results.append({
                "name": ida_segment.get_segm_name(seg),
                "start_ea": f"0x{seg.start_ea:x}",
                "end_ea": f"0x{seg.end_ea:x}",
                "size": seg.end_ea - seg.start_ea,
                "class": ida_segment.get_segm_class(seg),
                "perms": perm_str or "---",
                "bitness": 16 << seg.bitness,  # 0=16, 1=32, 2=64
            })

        return results

    def list_names(self, name_filter: str = "", limit: int = 500) -> dict:
        import idautils

        results = []
        total = 0
        name_filter_lower = name_filter.lower()

        for ea, name in idautils.Names():
            if name_filter_lower and name_filter_lower not in name.lower():
                continue
            total += 1
            if len(results) < limit:
                results.append({
                    "ea": f"0x{ea:x}",
                    "name": name,
                })

        return {"names": results, "total": total, "truncated": total > limit}

    # ── Types ─────────────────────────────────────────────────────────

    def list_structs(self, name_filter: str = "", limit: int = 500) -> dict:
        import idautils
        import idc

        results = []
        total = 0
        name_filter_lower = name_filter.lower()

        for idx, sid, name in idautils.Structs():
            if name_filter_lower and name_filter_lower not in name.lower():
                continue
            total += 1
            if len(results) < limit:
                results.append({
                    "ordinal": idx,
                    "name": name,
                    "size": idc.get_struc_size(sid),
                })

        return {"structs": results, "total": total, "truncated": total > limit}

    def get_struct_details(self, struct_name: str) -> dict:
        import ida_typeinf

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, struct_name):
            raise ValueError(f"Structure '{struct_name}' not found")

        if not tif.is_udt():
            raise ValueError(f"'{struct_name}' is not a struct/union type")

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            raise ValueError(f"Failed to get details for '{struct_name}'")

        members = []
        for i in range(udt.size()):
            m = udt.at(i)
            members.append({
                "offset": m.offset // 8,
                "name": m.name,
                "size": m.size // 8,
                "type": str(m.type) if not m.type.empty() else "",
            })

        return {
            "name": struct_name,
            "size": tif.get_size(),
            "is_union": tif.is_union(),
            "members": members,
        }

    def get_type_at(self, ea: int) -> str:
        import idc
        import ida_typeinf
        import ida_nalt

        t = idc.get_type(ea)
        if t:
            return t

        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea):
            return str(tif)

        return ""

    # ── Modify ────────────────────────────────────────────────────────

    def rename(self, ea: int, new_name: str) -> bool:
        import ida_name
        return ida_name.set_name(ea, new_name, ida_name.SN_CHECK)

    def set_comment(self, ea: int, comment: str, repeatable: bool = False) -> bool:
        import ida_bytes
        return ida_bytes.set_cmt(ea, comment, repeatable)

    def set_function_comment(self, ea: int, comment: str, repeatable: bool = False) -> bool:
        import ida_funcs
        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"No function at 0x{ea:x}")
        return ida_funcs.set_func_cmt(func, comment, repeatable)

    def set_type(self, ea: int, type_string: str) -> bool:
        import idc
        return idc.SetType(ea, type_string)

    # ── Search ────────────────────────────────────────────────────────

    def search_bytes(self, pattern: str, start: int = 0, max_results: int = 50) -> list[str]:
        import ida_bytes
        import ida_ida
        import ida_idaapi

        if start == 0:
            start = ida_ida.inf_get_min_ea()

        compiled = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled, start, pattern, 16)
        if err:
            raise ValueError(f"Invalid byte pattern: {pattern}")

        results = []
        ea = start
        end = ida_ida.inf_get_max_ea()
        while len(results) < max_results:
            ea, _ = ida_bytes.bin_search(
                ea, end, compiled, ida_bytes.BIN_SEARCH_FORWARD
            )
            if ea == ida_idaapi.BADADDR:
                break
            results.append(f"0x{ea:x}")
            ea += 1

        return results

    def search_text(self, text: str, start: int = 0, max_results: int = 50) -> list[dict]:
        import ida_search
        import ida_lines
        import ida_ida
        import ida_idaapi

        if start == 0:
            start = ida_ida.inf_get_min_ea()

        results = []
        ea = start
        for _ in range(max_results):
            ea = ida_search.find_text(
                ea, 0, 0, text, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
            )
            if ea == ida_idaapi.BADADDR:
                break
            line = ida_lines.tag_remove(
                ida_lines.generate_disasm_line(ea, 0)
            )
            results.append({"ea": f"0x{ea:x}", "line": line})

        return results

    def search_immediate(self, value: int, start: int = 0, max_results: int = 50) -> list[str]:
        import ida_search
        import ida_ida
        import ida_idaapi

        if start == 0:
            start = ida_ida.inf_get_min_ea()

        results = []
        ea = start
        for _ in range(max_results):
            ea, _ = ida_search.find_imm(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT, value)
            if ea == ida_idaapi.BADADDR:
                break
            results.append(f"0x{ea:x}")

        return results


class AsyncIDAClient:
    """Async bridge for IDAClient.

    All idalib operations are dispatched to a dedicated thread via
    ThreadPoolExecutor(max_workers=1). This ensures:
    1. All idalib calls happen on the same thread (single-threaded library)
    2. We don't block the asyncio event loop
    """

    def __init__(self, config: Config):
        self._config = config
        self._sync_client = IDAClient()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="idalib")

    async def _run(self, func, *args, **kwargs):
        """Run a sync function on the idalib thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, partial(func, *args, **kwargs))

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def initialize(self) -> str:
        return await self._run(self._sync_client.initialize)

    async def open_database(self, file_path: str, auto_analysis: bool = True) -> dict:
        return await self._run(self._sync_client.open_database, file_path, auto_analysis)

    async def close_database(self, save: bool = True) -> None:
        await self._run(self._sync_client.close_database, save)

    async def close(self) -> None:
        """Close any open database and shut down the executor."""
        try:
            if self._sync_client.is_db_open:
                await self.close_database(self._config.save_on_close)
        except Exception as e:
            logger.warning("Error closing database: %s", e)
        self._executor.shutdown(wait=False)

    # ── Properties (thread-safe reads) ────────────────────────────────

    @property
    def version(self) -> str:
        return self._sync_client.version

    @property
    def is_db_open(self) -> bool:
        return self._sync_client.is_db_open

    @property
    def has_hexrays(self) -> bool:
        return self._sync_client.has_hexrays

    # ── Core analysis ─────────────────────────────────────────────────

    async def list_functions(self, name_filter: str = "", limit: int = 500) -> dict:
        return await self._run(self._sync_client.list_functions, name_filter, limit)

    async def get_function_info(self, ea: int) -> dict:
        return await self._run(self._sync_client.get_function_info, ea)

    async def disassemble(self, ea: int, count: int = 30) -> list[dict]:
        return await self._run(self._sync_client.disassemble, ea, count)

    async def decompile(self, ea: int) -> str:
        return await self._run(self._sync_client.decompile, ea)

    # ── Cross-references ──────────────────────────────────────────────

    async def xrefs_to(self, ea: int, limit: int = 200) -> dict:
        return await self._run(self._sync_client.xrefs_to, ea, limit)

    async def xrefs_from(self, ea: int, limit: int = 200) -> dict:
        return await self._run(self._sync_client.xrefs_from, ea, limit)

    async def find_callers(self, ea: int, limit: int = 200) -> dict:
        return await self._run(self._sync_client.find_callers, ea, limit)

    # ── CFG / Graph ───────────────────────────────────────────────────

    async def get_basic_blocks(self, ea: int) -> dict:
        return await self._run(self._sync_client.get_basic_blocks, ea)

    async def get_call_graph(self, ea: int, depth: int = 2, direction: str = "both") -> dict:
        return await self._run(self._sync_client.get_call_graph, ea, depth, direction)

    async def get_block_disasm(self, ea: int, block_id: int) -> dict:
        return await self._run(self._sync_client.get_block_disasm, ea, block_id)

    async def get_function_cfg_summary(self, ea: int) -> dict:
        return await self._run(self._sync_client.get_function_cfg_summary, ea)

    # ── Enumeration ───────────────────────────────────────────────────

    async def list_strings(self, min_length: int = 5, filter_str: str = "", limit: int = 500) -> dict:
        return await self._run(self._sync_client.list_strings, min_length, filter_str, limit)

    async def list_imports(self, module_filter: str = "", limit: int = 1000) -> dict:
        return await self._run(self._sync_client.list_imports, module_filter, limit)

    async def list_exports(self, name_filter: str = "", limit: int = 1000) -> dict:
        return await self._run(self._sync_client.list_exports, name_filter, limit)

    async def list_segments(self) -> list[dict]:
        return await self._run(self._sync_client.list_segments)

    async def list_names(self, name_filter: str = "", limit: int = 500) -> dict:
        return await self._run(self._sync_client.list_names, name_filter, limit)

    # ── Types ─────────────────────────────────────────────────────────

    async def list_structs(self, name_filter: str = "", limit: int = 500) -> dict:
        return await self._run(self._sync_client.list_structs, name_filter, limit)

    async def get_struct_details(self, struct_name: str) -> dict:
        return await self._run(self._sync_client.get_struct_details, struct_name)

    async def get_type_at(self, ea: int) -> str:
        return await self._run(self._sync_client.get_type_at, ea)

    # ── Modify ────────────────────────────────────────────────────────

    async def rename(self, ea: int, new_name: str) -> bool:
        return await self._run(self._sync_client.rename, ea, new_name)

    async def set_comment(self, ea: int, comment: str, repeatable: bool = False) -> bool:
        return await self._run(self._sync_client.set_comment, ea, comment, repeatable)

    async def set_function_comment(self, ea: int, comment: str, repeatable: bool = False) -> bool:
        return await self._run(self._sync_client.set_function_comment, ea, comment, repeatable)

    async def set_type(self, ea: int, type_string: str) -> bool:
        return await self._run(self._sync_client.set_type, ea, type_string)

    # ── Search ────────────────────────────────────────────────────────

    async def search_bytes(self, pattern: str, start: int = 0, max_results: int = 50) -> list[str]:
        return await self._run(self._sync_client.search_bytes, pattern, start, max_results)

    async def search_text(self, text: str, start: int = 0, max_results: int = 50) -> list[dict]:
        return await self._run(self._sync_client.search_text, text, start, max_results)

    async def search_immediate(self, value: int, start: int = 0, max_results: int = 50) -> list[str]:
        return await self._run(self._sync_client.search_immediate, value, start, max_results)

    # ── DB info ───────────────────────────────────────────────────────

    async def get_db_info(self) -> dict:
        return await self._run(self._sync_client._get_db_info)
