"""
Driver Analysis Harness

This package provides automation scripts for batch processing Windows drivers
using the LPE-finder analysis pipeline.

Components:
- process_batch.py: Analyzes drivers and ranks them by vulnerability potential
- runner.py: Automates VM-based analysis with memory dumping
- integration.py: Integrates with the existing LPE-finder analysis pipeline
"""

__version__ = "1.0.0"
__author__ = "LPE-finder Team"

from .process_batch import DriverAnalyzer
from .runner import SSHManager, DriverLoader, AnalysisOrchestrator

__all__ = [
    'DriverAnalyzer',
    'SSHManager',
    'DriverLoader',
    'AnalysisOrchestrator',
]


