from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from analysis.symbolic_object import FunctionInfo


@dataclass
class AnalysisContext:
    all_functions: set[FunctionInfo] = field(default_factory=set)

    _instance: ClassVar[AnalysisContext | None] = None

    @classmethod
    def get(cls) -> AnalysisContext:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def reset(self) -> None:
        self.all_functions.clear()
