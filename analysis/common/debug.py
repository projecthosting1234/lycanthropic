from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from threading import Thread

from dashboard.new.emitter import NullEmitter

logger = logging.getLogger(__name__)
def add_parent(record):
    record.parent = os.path.basename(os.path.dirname(record.pathname))
    return True

logging.basicConfig(
    format="\033[34m%(parent)s/%(filename)s:%(lineno)d\033[0m\t\033[37m%(message)s\033[0m",
    level=logging.INFO,
)

logging.getLogger().handlers[0].addFilter(add_parent)

@dataclass
class DashboardBridge:
    emitter: object
    server_thread: Thread | None = None
    driver_path: str = ""
    pipeline_name: str = "analysis"
    port: int = 8000


_global_emitter: object = NullEmitter()
_global_bridge: DashboardBridge | None = None


def set_emitter(emitter: object) -> object:
    global _global_emitter
    _global_emitter = emitter
    return _global_emitter


def get_emitter() -> object:
    return _global_emitter


def emit(event_type: str, data: dict | None = None) -> None:
    get_emitter().emit(event_type, data or {})


def set_dashboard_bridge(bridge: DashboardBridge | None) -> DashboardBridge | None:
    global _global_bridge
    _global_bridge = bridge
    if bridge is not None:
        set_emitter(bridge.emitter)
    else:
        set_emitter(NullEmitter())
    return _global_bridge


def get_dashboard_bridge() -> DashboardBridge | None:
    return _global_bridge


def attach_dashboard(
    driver_path: str,
    *,
    port: int = 8000,
    no_browser: bool = False,
    pipeline_name: str = "analysis",
) -> DashboardBridge:
    from dashboard.new.launch import launch_dashboard

    emitter, server_thread = launch_dashboard(
        driver_path,
        port=port,
        no_browser=no_browser,
        pipeline_name=pipeline_name,
    )
    bridge = DashboardBridge(
        emitter=emitter,
        server_thread=server_thread,
        driver_path=driver_path,
        pipeline_name=pipeline_name,
        port=port,
    )
    set_dashboard_bridge(bridge)
    return bridge
