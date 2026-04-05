"""Pytest configuration and shared fixtures for SMT constraint tests."""

import sys
from pathlib import Path

# Add project root to sys.path so analysis package imports work
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Prevent analysis/__init__.py from loading (broken unrelated import chain)
import types
if 'analysis' not in sys.modules:
    _fake = types.ModuleType('analysis')
    _fake.__path__ = [str(Path(_PROJECT_ROOT) / 'analysis')]
    _fake.__package__ = 'analysis'
    sys.modules['analysis'] = _fake

import pytest

from analysis.ir_schema import (
    Constraint, Expr, ExprOp, Symbol,
)
from analysis.ir_to_z3.symbols import SymbolTable


@pytest.fixture
def simple_symbol_table():
    """A SymbolTable with universal root symbols + inbuf_base."""
    st = SymbolTable()
    st.add(Symbol(name='ioctl_code', sort=int, bitwidth=32, domain='ioctl_code', origin='root'))
    st.add(Symbol(name='in_len', sort=int, bitwidth=32, domain='length', origin='root'))
    st.add(Symbol(name='out_len', sort=int, bitwidth=32, domain='length', origin='root'))
    st.add(Symbol(name='x', sort=int, bitwidth=32, domain='test', origin='test'))
    st.add(Symbol(name='y', sort=int, bitwidth=32, domain='test', origin='test'))
    st.add(Symbol(name='inbuf_base', sort=int, bitwidth=64, domain='pointer', origin='test'))
    return st


