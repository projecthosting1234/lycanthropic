from __future__ import annotations

from pyclbr import Function
import re
import shutil
import subprocess
import time
import json

from pathlib import Path

import llvmlite.binding as llvm

from analysis.analysis_context import AnalysisContext
from analysis.common import ida_wrapper
from analysis.common.debug import logger
from analysis.symbolic_object import FunctionInfo, FunctionType, Callsite
import ida_funcs
import idautils
import ida_typeinf
import ida_hexrays
from pathlib import Path as _Path
import json as _json
import time as _time
import ida_ida
import idaapi
import ida_nalt
import ida_idp
import ida_hexrays as hr

builtin_intrinsics = [
    "_mm_lfence",
    "_mm_mfence",
    "_mm_pause",
    "_mm_prefetch",
    "_mm_prefetch",
]

def emit_prototype_from_pseudocode(info: FunctionInfo) -> str:
    pseudo_text = info.pseudocode
    logger.info("pseudo_text %s", pseudo_text)
    lines = [line.strip() for line in pseudo_text.splitlines() if line.strip()]
    if lines:
        first = lines[0].split("{")[0].strip()
        if not first.endswith(";"):
            first = f"{first};"
        return first
    return f"unsigned long long {info.func_name}(void);"


def emit_prototype_from_typeinfo(function_info: FunctionInfo) -> str:
    typeinfo = function_info.ida_typeinfo

    # u need to do this for imported functions
    if typeinfo.is_ptr():
        inner = typeinfo.get_pointed_object()
        if inner.is_func():
            typeinfo = inner

    func_type_data = ida_typeinf.func_type_data_t()
    typeinfo.get_func_details(func_type_data)
    func_cc = func_type_data.get_cc()
    rettype = str(typeinfo.get_rettype())
    prototype = ""

    prototype += rettype
    prototype += " " + function_info.func_name

    logger.info(
        "prototype_from_function_info func_type_data.rettype %s func_ea %s name  %s typeinfo %s",
        (rettype),
        hex(function_info.func_ea),
        function_info.func_name,
        typeinfo,
    )
    prototype += " ("
    for i, arg in enumerate(func_type_data):

        
        arg_name = arg.name  # str, may be empty
        arg_type = str(arg.type)  # tinfo_t -> string, e.g. "PIRP"
        arg_flags = arg.argloc  # argloc_t — stack offset or register

        logger.info("  arg[%d] %s %s  @ %s", i, arg_type, arg_name, repr(arg.argloc))
        prototype += f"{arg_type} {arg_name}, "
        logger.info("  func_cc %s", func_cc)

    if ida_typeinf.is_vararg_cc(func_cc):
        prototype += "..."

    prototype = prototype.rstrip(", ")
    prototype += ");"
    logger.info("prototype %s", prototype)

    return prototype


def emit_empty_stub(function_info: FunctionInfo) -> str:
    result = emit_prototype_from_typeinfo(function_info).rstrip(";")

    if result.startswith("void"):
        result = result + " { return; }"
    else:
        result = result + " { return 0; }"

    function_info.pseudocode = result
    logger.info("emit_empty_stub function_info.pseudocode %s", function_info.pseudocode)
    return result


def emit_intrinsic_stub(function_info: FunctionInfo) -> str:
    result = emit_prototype_from_typeinfo(function_info).rstrip(";")
    
    result = result + f" __asm__({ida_wrapper.name_from_address(function_info.func_ea)});"

    function_info.pseudocode = result
    logger.info("emit_intrinsic_stub function_info.pseudocode %s ea %s", function_info.pseudocode, hex(function_info.func_ea))
    return result

def _gather_callsites(cfunc: ida_hexrays.cfuncptr_t) -> list[Callsite]:

    class MyVisitor(ida_hexrays.ctree_visitor_t):
        callsites: list[Callsite] = []

        def __init__(self):
            # CV_FAST: fast traversal, CV_PARENTS: to allow parent tracking
            super().__init__(ida_hexrays.CV_PARENTS)

        @staticmethod
        def _get_callee_info(ea: int, call_expr: object) -> Callsite | None:
            """Return (callee_ea, callee_name). Handles cot_obj (direct calls) and cot_helper (intrinsics)."""

            if not call_expr:
                logger.info(
                    "unknown call at %s with expression %s", hex(ea), str(call_expr)
                )
                return None
            if call_expr.op == hr.cot_helper:

                if call_expr.helper in builtin_intrinsics:
                    logger.info("helper function %s is not a builtin intrinsic", call_expr.helper)
                    return None

                logger.info(
                    "myvisitor helper function callsite address %s named %s call type %s",
                    hex(ea),
                    call_expr.helper,
                    call_expr.type
                )
                callee_callsite = Callsite(ea, None, call_expr.helper)
                callee_callsite.callee_ref = FunctionInfo(
                    ea, call_expr.helper, FunctionType.INTRINSIC, call_expr.type
                )
                AnalysisContext.get().all_functions.add(callee_callsite.callee_ref)

                return callee_callsite
            if call_expr.op == hr.cot_obj:
                logger.info(
                    "myvisitor callee address %s callee name %s callsite address %s function  calltype %s",
                    hex(call_expr.obj_ea),
                    ida_wrapper.name_from_address(call_expr.obj_ea),
                    hex(ea),
                    call_expr.type
                )
                callee_callsite = Callsite(
                    ea,
                    call_expr.obj_ea,
                    ida_wrapper.name_from_address(call_expr.obj_ea),
                )

                usage_type = (
                    FunctionType.API
                    if ida_wrapper.is_import(call_expr.obj_ea)
                    else FunctionType.NONCHAIN
                )

                callee_callsite.callee_ref = FunctionInfo(
                    call_expr.obj_ea,
                    ida_wrapper.name_from_address(call_expr.obj_ea),
                    usage_type,
                    call_expr.type
                )
                AnalysisContext.get().all_functions.add(callee_callsite.callee_ref)

                return callee_callsite
            return None

        def visit_expr(self, e: ida_hexrays.ctree_node_t) -> int:
            # Print address and type of each expression
            #       logger.info(f"Expr: {e.opname} at {hex(e.ea)}")
            if e.op == hr.cot_call:
                callee_callsite = self._get_callee_info(e.ea, e.x)
                if callee_callsite:
                    MyVisitor.callsites.append(callee_callsite)
            return 0  # 0 means continue traversal

    if cfunc:
        visitor = MyVisitor()
        visitor.apply_to(cfunc.body, None)
        return visitor.callsites


def add_decompilation_to_workbench(func_ea: int, workbench_dir: str | Path) -> Path:
    """Dump one function's pseudocode into workbench/decompiled and register prototype."""
    wb = Path(workbench_dir)
    decompiled_dir = wb / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)

    original_name = ida_wrapper.name_from_address(func_ea)
    try:
        cfunc, _coord = ida_wrapper.get_pseudocode(func_ea)
        pseudocode = str(cfunc)
        logger.info("got pseudocode for %s: %s", original_name, pseudocode)
    except Exception as exc:
        logger.warning("fallback to stub pseudocode for %s: %s", original_name, exc)
        pseudocode = f"unsigned long long {original_name}(void) {{ return 0; }}"

    c_path = decompiled_dir / f"{original_name}.c"
    logger.info("added decompilation func=%s path=%s", original_name, c_path)
    context = AnalysisContext.get()
    callees = _gather_callsites(cfunc)

    for c in callees:
        logger.info(
            "callsite address %s callee address %s callee name %s",
            hex(c.callsite_ea),
            hex(c.callee_ea) if c.callee_ea else "unknown",
            c.callee_name,
        )

        if c.callee_ref.function_type == FunctionType.API or c.callee_ref.function_type == FunctionType.NONCHAIN:
            emit_empty_stub(c.callee_ref)
        if c.callee_ref.function_type == FunctionType.INTRINSIC:
            emit_empty_stub(c.callee_ref)

    thisfunc_info = FunctionInfo(func_ea, original_name, FunctionType.CHAIN)
    thisfunc_info.pseudocode = pseudocode
    thisfunc_info.ida_cfunc = cfunc
    thisfunc_info.callees = list(callees)
    context.all_functions.add(thisfunc_info)

    # regex search and prepend all API type functions with __imp_ prefix with for through all_functions
    for function in AnalysisContext.get().all_functions:
        if function.function_type == FunctionType.API:
            normalized_import_name = function.func_name.replace("__imp_", "")

            re_standalone_word = rf"\b{re.escape(normalized_import_name)}\b"
            replacement_str = f"__imp_{normalized_import_name}"
            thisfunc_info.pseudocode = re.sub(
                re_standalone_word, lambda m: replacement_str, thisfunc_info.pseudocode
            )

    return c_path


MAKEFILE_TEMPLATE_PATH = Path(__file__).resolve().parent / "makefile"


def init_workbench(output_dir: str | Path) -> Path:
    workbench_dir = Path(output_dir) / "workbench"
    if workbench_dir.exists():
        for item in workbench_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    workbench_dir.mkdir(parents=True, exist_ok=True)
    (workbench_dir / "decompiled").mkdir(parents=True, exist_ok=True)

    AnalysisContext.get().reset()
    return workbench_dir


def _write_makefile_template(workbench_dir: Path) -> None:
    template = MAKEFILE_TEMPLATE_PATH.read_text()
    template = template.replace(
        "WORKBENCH := $(CURDIR)",
        f"WORKBENCH := {workbench_dir}",
        1,
    )
    template = template.replace("combined.exe:", "combined.bc:", 1)
    template = template.replace(
        "\tlld-link $(DECOMPILED_BC) /out:$@ /opt:lldlto=0 /opt:noref /opt/noicf /debug /nodefaultlib /entry:main",
        "\tlld-link $(DECOMPILED_BC) -o $@ /mllvm:-O0",
        1,
    )
    template = template.replace(
        "\trm -f $(DECOMPILED_BC) combined.exe combined.ll",
        "\trm -f $(DECOMPILED_BC) combined.bc combined.ll",
        1,
    )
    (workbench_dir / "Makefile").write_text(template, encoding="utf-8")


def llvm_from_decompilation(
    workbench_dir: str | Path,
) -> tuple[Path, dict[str, dict[str, list[str] | str]]]:
    wb = Path(workbench_dir)
    _write_makefile_template(wb)
    _write_artifacts_to_disk(wb)
    _run_make(wb)
    bitcode_path = wb / "combined.bc"
    cfgs = _load_cfgs_from_bitcode(bitcode_path)
    return bitcode_path, cfgs


def _run_make(workbench_dir: Path) -> None:
    make_cmd = shutil.which("make") or shutil.which("mingw32-make")
    if not make_cmd:
        raise RuntimeError("Neither 'make' nor 'mingw32-make' is available in PATH.")
    logger.info("building llvm bitcode in %s", workbench_dir)
    subprocess.run([make_cmd], cwd=workbench_dir, check=True)


def _write_function_source(
    workbench_dir: Path, info: FunctionInfo, include_headers: bool = True
) -> None:
    decompiled_dir = workbench_dir / "decompiled"
    decompiled_dir.mkdir(parents=True, exist_ok=True)
    path = decompiled_dir / f"{info.func_name}.c"
    pseudo = info.pseudocode.strip()
    if not pseudo:
        pseudo = f"unsigned long long {info.func_name}(void) {{ return 0; }}"
    includes = (
        '#include "typedefs.h"\n'
        '#include "api_funcs.hpp"\n'
        '#include "local_funcs.hpp"\n'
        '#include "intrinsics.hpp"\n\n'
        if include_headers
        else ""
    )
    path.write_text(f"{includes}{pseudo}\n", encoding="utf-8")


def _write_sources_to_disk(workbench_dir: Path) -> None:
    ctx = AnalysisContext.get()
    for info in ctx.all_functions:
        _write_function_source(workbench_dir, info, include_headers=True)


def _write_prototypes_to_disk(workbench_dir: Path) -> None:
    ctx = AnalysisContext.get()

    def write_header(path: Path, infos: set[FunctionInfo]) -> None:
        prototypes = sorted({emit_prototype_from_pseudocode(info) for info in infos})

        for info in infos:
            logger.info("_prototype_for(info) %s", emit_prototype_from_pseudocode(info))

        if prototypes:

            path.write_text("\n".join(prototypes) + "\n", encoding="utf-8")
        else:
            path.write_text("", encoding="utf-8")

    api_funcs = {
        info for info in ctx.all_functions if info.function_type == FunctionType.API
    }
    local_funcs = {
        info for info in ctx.all_functions if info.function_type == FunctionType.NONCHAIN or info.function_type == FunctionType.CHAIN
    }
    intrinsics = {
        info for info in ctx.all_functions if info.function_type == FunctionType.INTRINSIC
    }

    write_header(workbench_dir / "api_funcs.hpp", api_funcs)
    write_header(workbench_dir / "local_funcs.hpp", local_funcs)
    write_header(workbench_dir / "intrinsics.hpp", intrinsics)

class _TypeHeaderSink(ida_typeinf.text_sink_t):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def _print(self, line: str) -> int:

        myline = line.strip()

        if "#define" in myline or "typedef" in myline:
            define_line = myline[:-1].split()
            if "wchar_t" in define_line[-1]:  # we cannot typedef wchar_t in C++
                myline = ""

        if "$" in myline and "[" in myline:

            # handle that retarded quirk with last_struct_field[1]

            type_name = ("$" + myline.split("$")[1]).split()[0]
            logger.info("type_name: %s line: %s", type_name, myline)
            anon_tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            anon_tif.get_named_type(til, type_name)
            elem_size = anon_tif.get_size()

            myline = myline.replace(
                type_name, "unsigned char paddinggg[%d]; //" % elem_size
            )
        
        if ("union _LARGE_INTEGER" in myline and "QuadPart" in myline):
            # Special handling for _LARGE_INTEGER and _IO_STATUS_BLOCK
            myline = myline.replace(" __s0", "")
        if ("struct _IO_STATUS_BLOCK" in myline and "Pointer" in myline):
            # Special handling for _IO_STATUS_BLOCK
            myline = myline.replace(" ___u0", "")

        self.lines.append(myline)
        return 0


def _write_typedefs_to_disk(workbench_dir: Path) -> None:

    sink = _TypeHeaderSink()
    til = ida_typeinf.get_idati()
    cc = ida_ida.compiler_info_t()
    cc.id = ida_typeinf.COMP_GNU
    ida_typeinf.set_compiler(
        cc, ida_typeinf.SETCOMP_OVERRIDE | ida_typeinf.SETCOMP_ONLY_ID
    )

    ord_qty = ida_typeinf.get_ordinal_count(til)
    ordinals = list(range(0, ord_qty))
    flags = (
        ida_typeinf.PDF_INCL_DEPS
        | ida_typeinf.PDF_HEADER_CMT
        | ida_typeinf.PDF_NO_ANON_NAME
        | ida_typeinf.PDF_DEF_BASE
        | ida_typeinf.PDF_DEF_FWD
    )
    ida_typeinf.print_decls(sink, til, ordinals, flags)
    target = workbench_dir / "typedefs.h"

    _BASE_TYPES = """\
        #define __hex
        #define __oct
        #define __bin
        #define __udec
        #define __sdec
        #define __offset(x)
        #define _BYTE unsigned char
        #define _WORD  unsigned short
        #define _DWORD unsigned int
        #define _QWORD unsigned long long
        """
    content = _BASE_TYPES + "\n"
    content += "\n".join(sink.lines)
    if content:
        content += "\n"
    target.write_text(content, encoding="utf-8")


def _write_artifacts_to_disk(workbench_dir: Path) -> None:
    _write_typedefs_to_disk(workbench_dir)
    _write_sources_to_disk(workbench_dir)
    _write_prototypes_to_disk(workbench_dir)


def _load_cfgs_from_bitcode(
    bitcode_path: Path,
) -> dict[str, dict[str, list[str] | str]]:
    if not bitcode_path.exists():
        raise FileNotFoundError(bitcode_path)
    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    module = llvm.parse_bitcode(bitcode_path.read_bytes())
    cfg_by_function: dict[str, dict[str, list[str] | str]] = {}
    for func in module.functions:
        if func.is_declaration:
            continue
        block_names: list[str] = []
        edges: list[str] = []
        for block in func.blocks:
            bname = str(block.name) or "<anon>"
            block_names.append(bname)
            term = str(block.instructions[-1]) if block.instructions else ""
            if " label %" in term:
                for part in term.split("label %")[1:]:
                    target = part.split(",")[0].split("]")[0].strip()
                    edges.append(f"{bname}->{target}")
        cfg_by_function[str(func.name)] = {
            "blocks": block_names,
            "edges": edges,
        }
    return cfg_by_function
