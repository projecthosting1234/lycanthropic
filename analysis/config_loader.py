"""Configuration loader for LPE-finder analysis pipeline.

Loads configuration from the root config.json file and provides
access to analysis-specific settings including sink definitions,
taint seeds, and LLM configuration.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from venv import logger

# Project root - used to locate config.json
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _PROJECT_ROOT / "config.json"

# Cache for loaded config
_config_cache: dict[str, Any] | None = None


def load_config() -> dict[str, Any]:
    """Load the root configuration from config.json.
    
    Returns:
        Dictionary containing the full configuration.
        
    Raises:
        FileNotFoundError: If config.json does not exist.
        json.JSONDecodeError: If config.json is invalid.
    """
    global _config_cache
    
    if _config_cache is not None:
        return _config_cache
    
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {_CONFIG_PATH}\n"
            f"Please create config.json in the project root directory."
        )
    
    with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
        _config_cache = json.load(f)
    
    return _config_cache


def reload_config() -> dict[str, Any]:
    """Force reload the configuration from disk.
    
    Returns:
        Dictionary containing the full configuration.
    """
    global _config_cache
    _config_cache = None
    return load_config()


def get_analysis_config() -> dict[str, Any]:
    """Get the analysis section of the configuration.
    
    Returns:
        Dictionary containing analysis settings including:
        - sink_definitions
        - taint_seeds
    """
    config = load_config()
    return config.get("analysis", {})


def get_harness_config() -> dict[str, Any]:
    """Get the harness section of the configuration.
    
    Returns:
        Dictionary containing harness settings including:
        - vm_name, ssh settings
        - windbg configuration
        - paths for sorted_dir, results_dir
    """
    config = load_config()
    return config.get("harness", {})


def get_hyperv_config() -> dict[str, Any]:
    """Get the Hyper-V pipeline section of the configuration.

    Returns:
        Dictionary containing Hyper-V settings including:
        - images_dir, diffs_dir
        - guest credentials and VM parameters
        - timeout and parallelism settings
    """
    config = load_config()
    return config.get("hyperv", {})


def get_vmware_config() -> dict[str, Any]:
    """Get the VMware Workstation section of the configuration.

    Returns:
        Dictionary containing VMware settings including:
        - golden_vmx, golden_vmdk paths
        - instance_dir, vmrun_bin, vdiskmanager_bin
        - pipe_name, memory_mb, cpu_cores
        - guest credentials and display mode
    """
    config = load_config()
    return config.get("vmware", {})


def get_sink_definitions() -> list[dict]:
    """Get targeted sink definitions from config.
    
    Returns:
        List of targeted sink definition dictionaries with new tag-based structure.
    """
    return get_analysis_config().get("sink_definitions", [])


def get_sink_by_name(sink_name: str) -> dict | None:
    """Get sink definition by name from sink_definitions.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        Sink definition dictionary or None if not found.
    """
    sinks = get_sink_definitions()
    for sink in sinks:
        if sink.get("label") == sink_name:
            return sink
    return None


def get_parameters_for_sink(sink_name: str) -> list:
    """Get parameter definitions for a specific sink.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        List of parameter dictionaries with idx, name, and tags.
    """
    sink = get_sink_by_name(sink_name)
    if sink:
        return sink.get("parameters", [])
    return []

def get_data_sink_params(sink_name: str) -> list[dict]:
    """Get parameter indices that are data sinks for arbitrary write detection.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        List of parameter indices that have DATA_SINK tag.
    """

    params = get_parameters_for_sink(sink_name)

    data_sink_params = []

    for p in params: 
        if "DATA_SINK" in p.get("tags", []):
            data_sink_params.append(p)
    return data_sink_params


def get_data_source_params(sink_name: str) -> list[dict]:
    """Get parameter indices that are data sources for arbitrary write detection.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        List of parameter indices that have DATA_SOURCE tag.
    """
    params = get_parameters_for_sink(sink_name)
    data_source_params = []

    for p in params: 
        if "DATA_SOURCE" in p.get("tags", []):
            data_source_params.append(p)
    return data_source_params


def get_size_params(sink_name: str) -> list[int]:
    """Get parameter indices that are size parameters for overflow detection.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        List of parameter indices that have SIZE tag.
    """
    params = get_parameters_for_sink(sink_name)
    size_params = []
    for p in params:
        if "SIZE" in p.get("tags", []):
            size_params.append(p)
    return size_params
    

def get_missing_validation_params(sink_name: str) -> list[int]:
    """Get parameter indices that are data sources for arbitrary write detection.
    
    Args:
        sink_name: Name of the sink to look up.
        
    Returns:
        List of parameter indices that have DATA_SOURCE tag.
    """
    params = get_parameters_for_sink(sink_name)
    return [p["param_id"] for p in params if "MISSING_VALIDATION" in p.get("tags", [])]

def is_arbitrary_write_sink(sink_name: str) -> bool:
    """Check if a sink can be used for arbitrary write attacks.
    
    Args:
        sink_name: Name of the sink to check.
        
    Returns:
        True if sink has both DATA_SINK and DATA_SOURCE parameters.
    """
    data_sink_params = get_data_sink_params(sink_name)
    data_source_params = get_data_source_params(sink_name)
    return len(data_sink_params) > 0 and len(data_source_params) > 0


def is_overflow_sink(sink_name: str) -> bool:
    """Check if a sink can be used for overflow attacks.
    
    Args:
        sink_name: Name of the sink to check.
        
    Returns:
        True if sink has SIZE parameters.
    """
    size_params = get_size_params(sink_name)
    return len(size_params) > 0


def is_missing_validation_sink(sink_name: str) -> bool:
    """Check if a sink requires input validation and can be vulnerable to missing validation.
    
    Args:
        sink_name: Name of the sink to check.
        
    Returns:
        True if sink is in the sensitive functions list that require validation.
    """
    # Sensitive functions that require input validation
    sensitive_functions = {
        "WRMSR",
        "MmMapIoSpace", 
        "MmMapIoSpaceWithKnownPhysicalMask",
        "ZwMapViewOfSection",
        "ZwWriteFile",
        "ZwDeviceIoControlFile",
    }
    return sink_name in sensitive_functions


def get_config_path() -> Path:
    """Get the path to the configuration file.

    Returns:
        Path object pointing to config.json.
    """
    return _CONFIG_PATH


# ── Tracer config accessors ─────────────────────────────────────


def get_tracer_config() -> dict[str, Any]:
    """Tracer limits: max_depth, max_backtracks, etc."""
    return get_analysis_config().get("tracer", {})


def get_tracer_max_depth() -> int:
    """Maximum climb depth before terminating a trace."""
    return get_tracer_config().get("max_depth", 15)


def get_tracer_max_backtracks() -> int:
    """Maximum backtrack attempts per trace."""
    return get_tracer_config().get("max_backtracks", 3)


# ── SMT config accessors ────────────────────────────────────────


def get_smt_config() -> dict[str, Any]:
    """SMT settings: timeout_ms, enable_repair, etc."""
    return get_analysis_config().get("smt", {})


def get_smt_timeout_ms() -> int:
    """SMT solver timeout in milliseconds."""
    return get_smt_config().get("timeout_ms", 30000)



def load_key_from_env_file(env_key: str) -> str | None:
    """Load a specific environment variable from .env file in project root.
    
    Args:
        env_key: The environment variable name to look for (e.g., "OPENAI_API_KEY")
        
    Returns:
        The value of the key if found, None otherwise.
    """
    env_file = _PROJECT_ROOT / ".env"
    if not env_file.exists():
        return None
    
    try:
        # Parse .env file
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                # Parse KEY=VALUE format
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    if key == env_key:
                        return value
    except Exception as e:
        logger.info(f"[!] Warning: Failed to parse .env file: {e}")
    
    return None


# ── Dashboard config accessors ──────────────────────────────────


def get_dashboard_config() -> dict[str, Any]:
    """Dashboard queue sizes."""
    return get_analysis_config().get("dashboard", {})


# ── LLM config accessors ────────────────────────────────────────

def get_llm_config() -> dict[str, Any]:
    """Get the LLM section of the configuration.
    
    Returns:
        Dictionary containing LLM settings including:
        - default_provider, default_model
        - provider-specific settings
    """
    config = load_config()
    return config.get("llm", {})

def get_llm_max_tokens() -> int:
    """Default max tokens for LLM calls."""
    return get_llm_config().get("max_tokens", 50000)


def get_advanced_extraction() -> int:
    """Get the advanced_extraction flag from llm config.

    Returns:
        -1: never use pro model
         0: auto retry with pro on failure (default)
         1: always use pro model
    """
    return get_llm_config().get("advanced_extraction", 0)


def get_pro_model() -> str:
    """Get the pro model identifier for LLM escalation.

    Returns:
        Model string, defaults to 'gpt-5.4-pro-2026-03-05'.
    """
    return get_llm_config().get("pro_model", "gpt-5.4-pro-2026-03-05")
