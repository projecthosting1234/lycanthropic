#!/usr/bin/env python3
"""Smoke tests for SSH channel output capture.

Validates that paramiko channel.recv() works correctly before running
the full 80-turn pipeline.  No pytest dependency — run directly:

    python tests/test_ssh_channel.py

Expects the debug VM to be running with OpenSSH Server accessible.
If the VM isn't running, attempts to start it via vmrun.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

# Add project root to path so we can import production code.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import paramiko

from windbg_mcp.tools.orchestrator import (
    _ssh_connect,
    _safe_close_ssh,
    EXPLOIT_USER,
    EXPLOIT_PASS,
    MAX_OUTPUT_BYTES,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_PATH = PROJECT_ROOT / "config.json"

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return json.load(f)


def discover_ip(cfg: dict, vmx: str) -> str:
    """Get guest IP via vmrun getGuestIPAddress."""
    for _ in range(5):
        r = subprocess.run(
            [cfg["vmrun_bin"], "-T", "ws", "getGuestIPAddress", vmx],
            capture_output=True, text=True, timeout=15,
        )
        ip = r.stdout.strip()
        if r.returncode == 0 and ip:
            return ip
        time.sleep(3)
    raise RuntimeError("Could not discover guest IP")


def ensure_vm_running(cfg: dict) -> str:
    """Ensure the debug instance VM is running, return guest IP."""
    vmx = str(Path(cfg.get("instance_dir", r"C:\VMs\instances\debug_instance"))
              / "debug_instance.vmx")
    vmrun = cfg["vmrun_bin"]

    # Check if already running
    r = subprocess.run(
        [vmrun, "list"], capture_output=True, text=True, timeout=15,
    )
    if vmx.lower().replace("\\", "/") in r.stdout.lower().replace("\\", "/"):
        print(f"  VM already running: {vmx}")
    else:
        print(f"  Starting VM: {vmx}")
        subprocess.run(
            [vmrun, "-T", "ws", "start", vmx, "nogui"],
            check=True, timeout=120,
        )
        print("  Waiting for VMware Tools...")
        time.sleep(30)

    return discover_ip(cfg, vmx)


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

PASSED = 0
FAILED = 0
ADMIN_USER = "Admin"
ADMIN_PASS = "P@ssw0rd!"


def test(name: str):
    """Decorator for test functions."""
    def decorator(fn):
        fn._test_name = name
        return fn
    return decorator


def run_test(fn, *args, **kwargs):
    global PASSED, FAILED
    name = getattr(fn, "_test_name", fn.__name__)
    print(f"\n--- Test {PASSED + FAILED + 1}: {name} ---")
    try:
        fn(*args, **kwargs)
        PASSED += 1
        print(f"  PASS")
    except Exception as e:
        FAILED += 1
        print(f"  FAIL: {e}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@test("Admin SSH whoami")
def test_admin_whoami(ip: str):
    """Test 1: SSH connectivity + admin creds."""
    ssh = _ssh_connect(ip, ADMIN_USER, ADMIN_PASS)
    try:
        _, stdout, _ = ssh.exec_command("whoami")
        result = stdout.read().decode().strip().lower()
        print(f"  whoami returned: {result!r}")
        assert "admin" in result, f"Expected 'admin' in output, got {result!r}"
    finally:
        _safe_close_ssh(ssh)


@test("ExploitTest SSH whoami")
def test_exploit_whoami(ip: str):
    """Test 2: Low-priv user can SSH."""
    ssh = _ssh_connect(ip, EXPLOIT_USER, EXPLOIT_PASS)
    try:
        _, stdout, _ = ssh.exec_command("whoami")
        result = stdout.read().decode().strip().lower()
        print(f"  whoami returned: {result!r}")
        assert "exploittest" in result, f"Expected 'exploittest' in output, got {result!r}"
    finally:
        _safe_close_ssh(ssh)


@test("ExploitTest exec_command + channel.recv()")
def test_channel_recv(ip: str):
    """Test 3: Channel output capture via recv() works."""
    ssh = _ssh_connect(ip, EXPLOIT_USER, EXPLOIT_PASS)
    try:
        _, stdout_ch, _ = ssh.exec_command("echo HELLO")
        channel = stdout_ch.channel
        channel.settimeout(5.0)

        # Drain using the same pattern as production code
        chunks = []
        try:
            while True:
                chunk = channel.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass

        data = b"".join(chunks)
        text = data.decode("utf-8", errors="replace").strip()
        print(f"  recv() returned: {text!r}")
        assert "HELLO" in text, f"Expected 'HELLO' in output, got {text!r}"
    finally:
        _safe_close_ssh(ssh)


@test("Quoted path: whoami.exe via exec_command")
def test_quoted_path(ip: str):
    """Test 4: Path quoting through OpenSSH works."""
    ssh = _ssh_connect(ip, EXPLOIT_USER, EXPLOIT_PASS)
    try:
        cmd = '"C:\\Windows\\System32\\whoami.exe"'
        _, stdout_ch, _ = ssh.exec_command(cmd)
        channel = stdout_ch.channel
        channel.settimeout(5.0)

        chunks = []
        try:
            while True:
                chunk = channel.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass

        data = b"".join(chunks)
        text = data.decode("utf-8", errors="replace").strip().lower()
        print(f"  whoami.exe returned: {text!r}")
        assert "exploittest" in text or "admin" in text, \
            f"Expected username in output, got {text!r}"
    finally:
        _safe_close_ssh(ssh)


@test("Timeout fires on long-running command, no hang")
def test_timeout_no_hang(ip: str):
    """Test 5: socket.timeout fires within expected time, no data loss."""
    ssh = _ssh_connect(ip, EXPLOIT_USER, EXPLOIT_PASS)
    try:
        # 'timeout /t 30' blocks for 30 seconds — our recv timeout should fire first
        # Use 'ping -n 31 127.0.0.1' as alternative (timeout /t needs console)
        _, stdout_ch, _ = ssh.exec_command("ping -n 31 127.0.0.1")
        channel = stdout_ch.channel
        channel.settimeout(2.0)

        t0 = time.monotonic()
        chunks = []
        try:
            while True:
                chunk = channel.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        elapsed = time.monotonic() - t0

        data = b"".join(chunks)
        text = data.decode("utf-8", errors="replace")
        print(f"  Timeout fired after {elapsed:.1f}s, captured {len(data)} bytes")
        print(f"  Partial output preview: {text[:120]!r}")

        # Should complete within 5s (2s timeout + recv overhead), not 30s
        assert elapsed < 5.0, f"Took {elapsed:.1f}s — timeout didn't fire properly"
        # Should have captured SOME output (ping preamble) — not lost
        assert len(data) > 0, "No data captured — partial data was lost!"
    finally:
        _safe_close_ssh(ssh)


@test("_safe_close_ssh on active session completes fast")
def test_safe_close(ip: str):
    """Test 6: transport.close() doesn't hang on active session."""
    ssh = _ssh_connect(ip, EXPLOIT_USER, EXPLOIT_PASS)
    # Start a long-running command to keep the session active
    ssh.exec_command("ping -n 60 127.0.0.1")

    t0 = time.monotonic()
    _safe_close_ssh(ssh)
    elapsed = time.monotonic() - t0

    print(f"  _safe_close_ssh completed in {elapsed:.2f}s")
    assert elapsed < 2.0, f"Close took {elapsed:.2f}s — too slow, may hang in production"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("SSH Channel Output Capture — Smoke Tests")
    print("=" * 60)

    cfg = load_config()
    ip = ensure_vm_running(cfg)
    print(f"  Guest IP: {ip}")

    # Run all tests sequentially
    run_test(test_admin_whoami, ip)
    run_test(test_exploit_whoami, ip)
    run_test(test_channel_recv, ip)
    run_test(test_quoted_path, ip)
    run_test(test_timeout_no_hang, ip)
    run_test(test_safe_close, ip)

    # Summary
    total = PASSED + FAILED
    print(f"\n{'=' * 60}")
    print(f"Results: {PASSED}/{total} passed, {FAILED} failed")
    print("=" * 60)

    if FAILED > 0:
        print("\nFix failures before running the full pipeline.")
        sys.exit(1)
    else:
        print("\nAll tests passed! Safe to run full pipeline:")
        print("  python run_driver_analysis.py dataset/BioNTdrv.sys --max-turns 80 --max-iterations 1")
        sys.exit(0)


if __name__ == "__main__":
    main()
