"""Configuration for the IDA Pro MCP server."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Server configuration loaded from environment variables."""
    ida_install_dir: str
    default_binary: str | None
    auto_analysis: bool
    save_on_close: bool
    max_results: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            ida_install_dir=os.environ.get(
                "IDA_MCP_IDA_DIR",
                r"C:\Program Files\IDA Professional 9.0",
            ),
            default_binary=os.environ.get("IDA_MCP_BINARY"),
            auto_analysis=os.environ.get("IDA_MCP_AUTO_ANALYSIS", "1") not in ("0", "false", "no"),
            save_on_close=os.environ.get("IDA_MCP_SAVE_ON_CLOSE", "1") not in ("0", "false", "no"),
            max_results=int(os.environ.get("IDA_MCP_MAX_RESULTS", "1000")),
        )
