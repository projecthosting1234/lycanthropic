"""Dashboard server — FastAPI WebSocket + static files on localhost.

Architecture:
  - Main thread runs uvicorn (async event loop)
  - Daemon thread runs the tracer (synchronous)
  - queue.Queue bridges them (thread-safe)
  - queue_bridge coroutine polls the queue and broadcasts to all WebSocket clients

Usage:
    python -m dashboard.server path/to/driver.sys [--port 8000]
"""

from __future__ import annotations

import asyncio
import json
import queue
import sys
import threading
import time
import webbrowser
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from contextlib import asynccontextmanager

# ---------------------------------------------------------------------------
# Shared event queue (main↔tracer bridge)
# ---------------------------------------------------------------------------

from analysis.sym_object_helper import get_dashboard_config as _get_dash_cfg

event_queue: queue.Queue = queue.Queue(maxsize=_get_dash_cfg().get("event_queue_size", 50_000))

# Fires when the first WebSocket client connects
_client_connected = threading.Event()

# Tracks the active analysis so reconnecting clients get server_ready
_active_session: dict | None = None
_session_lock = threading.Lock()


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        _client_connected.set()

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        msg = json.dumps(data)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)



manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Label shortening (server-side, immune to browser caching)
# ---------------------------------------------------------------------------

import re as _re

_MSVC_MANGLED = _re.compile(r'^\?(\w+)@(\w+)@@')


def _shorten_label(name: str, max_len: int = 30) -> str:
    """Shorten C++ mangled / long function names for graph display."""
    if not name or len(name) <= max_len:
        return name
    m = _MSVC_MANGLED.match(name)
    if m:
        func, cls = m.group(1), m.group(2)
        full = f"{cls}::{func}"
        if len(full) <= max_len:
            return full
        budget = max_len - len(func) - 5
        if budget >= 4:
            return f"{cls[:budget]}..::{func}"
        return func if len(func) <= max_len else func[:max_len - 3] + "..."
    if name.startswith("_ZN") or name.startswith("_Z"):
        return name[:max_len - 3] + "..."
    return name[:max_len - 3] + "..."


def _process_event(evt: dict) -> dict:
    """Post-process events before broadcasting to shorten labels."""
    etype = evt.get("type")
    data = evt.get("data")
    if not data:
        return evt
    if etype in ("sink_added", "node_discovered"):
        label = data.get("label", "")
        if len(label) > 30:
            data["_full_label"] = label
            data["label"] = _shorten_label(label)
    return evt


# ---------------------------------------------------------------------------
# Queue bridge coroutine
# ---------------------------------------------------------------------------

async def queue_bridge():
    """Drain the thread-safe queue and broadcast events to WebSocket clients."""
    global _active_session
    loop = asyncio.get_running_loop()
    while True:
        try:
            evt = await loop.run_in_executor(None, event_queue.get, True, 0.05)
            # Shorten long labels before sending to browser
            evt = _process_event(evt)
            # Track session state for reconnecting clients
            etype = evt.get("type")
            with _session_lock:
                if etype == "server_ready":
                    _active_session = evt
                elif etype in ("analysis_complete", "error"):
                    _active_session = None
            await manager.broadcast(evt)
        except queue.Empty:
            await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(queue_bridge())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan)


class NoCacheMiddleware(BaseHTTPMiddleware):
    """Prevent browser from caching any response during development."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.path != "/ws":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response


app.add_middleware(NoCacheMiddleware)

STATIC_DIR = Path(__file__).parent / "static"


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    # If analysis is already running, tell the new client so overlay hides
    with _session_lock:
        session = _active_session
    if session:
        try:
            await ws.send_text(json.dumps(session))
        except Exception:
            pass
    try:
        while True:
            await ws.receive_text()  # keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(ws)


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Entry point: parse args, launch tracer thread, start uvicorn
# ---------------------------------------------------------------------------

def _run_tracer(ida_file: str, mode: str):
    """Run the tracer in a daemon thread. Wraps the instrumented trace()."""
    from dashboard.new.emitter import TracerEventEmitter

    emitter = TracerEventEmitter(event_queue)

    # Wait for browser WebSocket to connect before emitting
    _client_connected.wait(timeout=30)
    time.sleep(0.3)

    emitter.emit("server_ready", {"file": ida_file, "mode": mode, "pipeline": "trace_only"})

    try:
        # Import the instrumented tracer
        _PROJECT_ROOT = Path(__file__).resolve().parent.parent
        if str(_PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(_PROJECT_ROOT))

        import importlib
        tracer_mod = importlib.import_module("analysis.4_tracer")

        # Inject the emitter into the tracer module
        tracer_mod._emitter = emitter

        result = tracer_mod.trace(ida_file, mode=mode)

        # Final summary
        emitter.emit("analysis_complete", {
            "findings": len(result.findings),
            "incomplete": len(result.incomplete),
            "file": ida_file,
        })
    except Exception as e:
        emitter.emit("error", {"message": str(e)})
        import traceback
        traceback.print_exc()
