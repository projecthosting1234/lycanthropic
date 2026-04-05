"""User-registered callbacks (Unicorn-style) for LLM assist and domain symbolization insertion points."""
from __future__ import annotations

from collections.abc import Callable

_domain_symbolize_callback: Callable | None = None
_trace_boundary_callback: Callable | None = None


def register_callback(slot: str, fn: Callable) -> None:
    global _domain_symbolize_callback, _trace_boundary_callback
    if slot == "domain_symbolize":
        _domain_symbolize_callback = fn
        return
    if slot == "trace_boundary":
        _trace_boundary_callback = fn
        return
    raise ValueError(f"unknown callback slot: {slot}")


def get_callback(slot: str) -> Callable | None:
    if slot == "domain_symbolize":
        return _domain_symbolize_callback
    if slot == "trace_boundary":
        return _trace_boundary_callback
    raise ValueError(f"unknown callback slot: {slot}")
