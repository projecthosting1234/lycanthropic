from __future__ import annotations

from pathlib import Path

from analysis.llvm_ir_emission.decompile_recompile import (
    add_decompilation_to_workbench,
    init_workbench,
    llvm_from_decompilation,
)


class LLVMIREmitter:
    def __init__(self, idb_path: str, output_dir: str | Path):
        self.idb_path = idb_path
        self.output_dir = Path(output_dir)
        self.workbench_dir = init_workbench(self.output_dir)
        self.cfg_by_function: dict[str, dict[str, list[str] | str]] = {}

    def add_decompilation(self, func_ea: int) -> Path:
        """Wrapper around add_decompilation_to_workbench."""
        return add_decompilation_to_workbench(func_ea, self.workbench_dir)

    def llvm_from_decompilation(self) -> Path:
        """Wrapper around decompile_recompile_pseudo + make + llvmlite CFG extraction."""
        bitcode_path, cfgs = llvm_from_decompilation(self.workbench_dir)
        self.cfg_by_function = cfgs
        return bitcode_path

    def llvm_from_lifter(self):
        return None
