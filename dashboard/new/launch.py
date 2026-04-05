"""Single implementation of dashboard launch and run-with-dashboard.

Used by analysis passes (e.g. Pass 1) when --dashboard is requested.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
import webbrowser
from pathlib import Path

from dashboard.new.emitter import TracerEventEmitter
# from dashboard.new.server import app, event_queue, _client_connected


def launch_dashboard(
    driver_path: str,
    *,
    top_n: int = 10,
    port: int = 8000,
    no_browser: bool = False,
    pipeline_name: str = "pass1",
):
    """Launch dashboard server and wait for client connection.

    Returns:
        (emitter, server_thread) for the caller to run the pipeline with emitter
        and then join server_thread as needed.
    """
    def _run_server():
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

    emitter = TracerEventEmitter(event_queue)
    server_thread = threading.Thread(target=_run_server, daemon=True)
    server_thread.start()

    if not no_browser:
        def _open():
            time.sleep(0.8)
            webbrowser.open(f"http://127.0.0.1:{port}")
        threading.Thread(target=_open, daemon=True).start()

    print(f"[*] Dashboard at http://127.0.0.1:{port} — waiting for browser...")
    _client_connected.wait(timeout=30)
    time.sleep(0.3)

    emitter.emit("server_ready", {
        "file": driver_path,
        "pipeline": pipeline_name,
    })

    return emitter, server_thread


def run_with_dashboard(
    driver_path: str,
    *,
    pipeline_fn,
    pipeline_name: str = "pass1",
    top_n: int = 10,
    port: int = 8000,
    no_browser: bool = False,
    **kwargs,
):
    """Run a pipeline with live dashboard visualization.

    Launches the dashboard, runs pipeline_fn(driver_path, ..., emitter=emitter)
    with the rest of kwargs, then keeps the server running until Ctrl+C.

    pipeline_fn: e.g. run_pass1_pipeline, called as
        pipeline_fn(driver_path, ..., emitter=emitter, **kwargs).
    """
    emitter, server_thread = launch_dashboard(
        driver_path,
        top_n=top_n,
        port=port,
        no_browser=no_browser,
        pipeline_name=pipeline_name,
    )

    try:
        result = pipeline_fn(driver_path, emitter=emitter, top_n=top_n, **kwargs)

        if result and "smt_results" in result:
            emitter.emit("pipeline_complete", {
                "findings_solved": len(result["smt_results"]),
                "smt_summaries": result["smt_results"],
                "file": driver_path,
            })
            print(f"\n{'='*60}")
            print(f"  PIPELINE SUMMARY ({len(result['smt_results'])} findings)")
            print(f"{'='*60}")
            for s in result["smt_results"]:
                print(f"  {s['finding']:30s} [{s['status'].upper()}]")
            sys.stdout.flush()

        return result
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        emitter.emit("error", {"message": f"{e}\n\n{tb}"})
        print(f"\n[!] Pipeline error:\n{tb}", file=sys.stderr)
        sys.stderr.flush()
        raise
    finally:
        print(f"\n[*] Dashboard still running at http://127.0.0.1:{port}")
        print("[*] Press Ctrl+C to exit.")
        sys.stdout.flush()
        try:
            while server_thread.is_alive():
                server_thread.join(timeout=0.5)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            sys.exit(0)
