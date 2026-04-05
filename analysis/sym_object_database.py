from __future__ import annotations

import json
from pathlib import Path

from .common.debug import logger
from .symbolic_object import Sink, TraceDestination, TaintedVar
from typing import Any

"""Symbolic object loader for LPE-finder analysis pipeline.

Loads stuff like params, allocation sites, sinks from the root config.json file.
provides helper functions for gathering lists of objects
"""

# Project root - used to locate config.json
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config.json"


def load_sink_definitions(config_path: str | None = None) -> list[Sink]:
    cfg_path = (
        Path(config_path)
        if config_path is not None
        else Path(__file__).resolve().parent.parent / "config.json"
    )

    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    sinks: list[Sink] = []

    for sink_data in data.get("analysis", {}).get("sink_definitions", []):
        sink_name = sink_data.get("label", "")
        sink_tags = tuple(str(tag) for tag in sink_data.get("tags", []))

        parameters: list[TaintedVar] = []

        for param in sink_data.get("parameters", []):
            description = str(
                param.get("description", f"param_{param.get('param_id', 0)}")
            )
        
            parameters.append(
                TaintedVar(
                    name=f"{sink_name}:{description}",
                    param_index=int(param.get("param_id", 1)),
                    bitwidth=64,
                    trace_dest=TraceDestination.ENTRY_POINT,
                    taint_boundary_name=sink_name,
                    tags=tuple(str(tag) for tag in param.get("tags", [])),
                    description=description,
                    sink_tags=sink_tags,
                )
            )

        sinks.append(
            Sink(
                label=sink_name,
                tags=sink_tags,
                initial_callers=tuple(
                    str(item) for item in sink_data.get("initial_callers", [])
                ),
                imports=tuple(str(item) for item in sink_data.get("imports", [])),
                asm=tuple(str(item) for item in sink_data.get("asm", [])),
                functions=tuple(str(item) for item in sink_data.get("functions", [])),
                parameters=parameters,
            )
        )

    sink_names = ", ".join(sink.label for sink in sinks)

    logger.info("loaded %d sinks, %s", len(sinks), sink_names)

    return sinks
