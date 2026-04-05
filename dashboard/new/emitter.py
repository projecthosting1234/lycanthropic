"""TracerEventEmitter — thread-safe event bridge for the visualization dashboard.

This module provides a single emit() method that puts JSON-serializable events
into a queue.Queue. The FastAPI WebSocket server drains this queue and broadcasts
to all connected browser clients.

The emitter is designed to be injected into 4_tracer.py with zero changes to the
tracer's control flow. Every emit() call is non-blocking (put_nowait) and will
silently drop events under backpressure rather than stalling the analysis.

Usage:
    from dashboard.new.emitter import TracerEventEmitter, NullEmitter
    import queue

    from analysis.config_loader import get_dashboard_config
    q = queue.Queue(maxsize=get_dashboard_config().get("emitter_queue_size", 10_000))
    emitter = TracerEventEmitter(q)

    # or, when running without the dashboard:
    emitter = NullEmitter()
"""

from __future__ import annotations

import queue
import time


class TracerEventEmitter:
    """Thread-safe event emitter that pushes to a queue.Queue."""

    def __init__(self, q: queue.Queue):
        self._q = q
        self._seq = 0

    def emit(self, event_type: str, data: dict | None = None):
        """Emit an event. Non-blocking; drops on backpressure."""
        self._seq += 1
        evt = {
            "seq": self._seq,
            "type": event_type,
            "ts": time.time(),
            "data": data or {},
        }
        try:
            self._q.put_nowait(evt)
        except queue.Full:
            pass  # never block the tracer


class NullEmitter:
    """No-op emitter for running without the dashboard."""

    def emit(self, event_type: str, data: dict | None = None):
        pass
