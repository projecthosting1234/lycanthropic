"""Tests for integrity mode flags and MCP tool behavior.

Verifies:
1. MCP tools: _run_verification validates files, calls verify() with correct integrity
2. MCP tools: _run_verify_direct calls verify() directly (no subprocess)
3. MCP tools: compile_exploit handles missing source / missing vcvars
4. exploit_goal: constraints_section() and verification_section() adapt per mode
5. agent_prompt: build_analysis_prompt() shows/hides MCP tools per mode
6. iteration_loop: CLI arg parsing, mutual exclusivity, Phase 5 routing
7. verify_exploit: pipe isolation, no taskkill bomb, dispatch works
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest import mock

import pytest

from windows_exploit_dev import exploit_goal
from windows_exploit_dev.pipeline.agent_prompt import build_analysis_prompt

# ---------------------------------------------------------------------------
# Module-level: mock `mcp` package so compile_and_verify can import
# ---------------------------------------------------------------------------

_fake_mcp = types.ModuleType("mcp")
_fake_server = types.ModuleType("mcp.server")
_fake_fastmcp = types.ModuleType("mcp.server.fastmcp")


class _FakeFastMCP:
    def __init__(self, *a, **kw):
        pass

    def tool(self):
        return lambda fn: fn

    def run(self, **kw):
        pass


class _FakeContext:
    pass


_fake_fastmcp.FastMCP = _FakeFastMCP
_fake_fastmcp.Context = _FakeContext
_fake_mcp.server = _fake_server
_fake_server.fastmcp = _fake_fastmcp

if "mcp" not in sys.modules:
    sys.modules["mcp"] = _fake_mcp
    sys.modules["mcp.server"] = _fake_server
    sys.modules["mcp.server.fastmcp"] = _fake_fastmcp

from windows_exploit_dev.mcp.pwntools.tools.compile_and_verify import (  # noqa: E402
    _run_verification,
    _run_verify_direct,
    compile_exploit,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ===========================================================================
# MCP tool: _run_verification (file checks + dispatch)
# ===========================================================================

class TestMCPRunVerification:
    def _mock_ctx(self):
        ctx = mock.MagicMock()
        ctx.request_context.lifespan_context = mock.MagicMock()
        return ctx

    def test_missing_exploit_returns_error_json(self):
        result_str = run_async(_run_verification(
            "C:\\nonexistent\\exploit.exe",
            "C:\\nonexistent\\driver.sys",
            "test_svc", 90, "high", self._mock_ctx(),
        ))
        result = json.loads(result_str)
        assert result["passed"] is False
        assert "exploit" in result["error"].lower()
        assert "not found" in result["error"].lower()

    def test_missing_driver_returns_error_json(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            exploit = f.name
        try:
            result_str = run_async(_run_verification(
                exploit, "C:\\nonexistent\\driver.sys",
                "svc", 90, "high", self._mock_ctx(),
            ))
            result = json.loads(result_str)
            assert result["passed"] is False
            assert "driver" in result["error"].lower()
        finally:
            os.unlink(exploit)

    def test_calls_verify_direct_with_high(self):
        """_run_verification should call _run_verify_direct with integrity='high'."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"x"); exploit = f.name
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(b"x"); driver = f.name

        captured = {}
        def fake_direct(ep, dp, sn, to, integ):
            captured.update({"integrity": integ, "service": sn, "timeout": to})
            return json.dumps({"passed": True})

        try:
            with mock.patch(
                "windows_exploit_dev.mcp.pwntools.tools.compile_and_verify._run_verify_direct",
                side_effect=fake_direct,
            ):
                run_async(_run_verification(
                    exploit, driver, "my_svc", 120, "high", self._mock_ctx()))
            assert captured["integrity"] == "high"
            assert captured["service"] == "my_svc"
            assert captured["timeout"] == 120
        finally:
            os.unlink(exploit); os.unlink(driver)

    def test_calls_verify_direct_with_medium(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"x"); exploit = f.name
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(b"x"); driver = f.name

        captured = {}
        def fake_direct(ep, dp, sn, to, integ):
            captured["integrity"] = integ
            return json.dumps({"passed": False})

        try:
            with mock.patch(
                "windows_exploit_dev.mcp.pwntools.tools.compile_and_verify._run_verify_direct",
                side_effect=fake_direct,
            ):
                run_async(_run_verification(
                    exploit, driver, "svc", 90, "medium", self._mock_ctx()))
            assert captured["integrity"] == "medium"
        finally:
            os.unlink(exploit); os.unlink(driver)


# ===========================================================================
# MCP tool: _run_verify_direct (calls verify() in-process)
# ===========================================================================

class TestRunVerifyDirect:
    def test_calls_verify_with_correct_args(self):
        """_run_verify_direct calls verify() with the right parameters."""
        mock_result = {"passed": True, "flag": "FLAG{x}", "exploit_stdout": "ok",
                       "integrity": "high"}

        with mock.patch(
            "windows_exploit_dev.verify_exploit.verify",
            return_value=mock_result,
        ) as m:
            result_str = _run_verify_direct(
                "C:\\e.exe", "C:\\d.sys", "svc", 120, "high")
            m.assert_called_once_with(
                exploit_path=Path("C:\\e.exe"),
                driver_path=Path("C:\\d.sys"),
                service_name="svc",
                exploit_timeout=120,
                integrity="high",
            )
        result = json.loads(result_str)
        assert result["passed"] is True

    def test_exception_returns_error_json(self):
        with mock.patch(
            "windows_exploit_dev.verify_exploit.verify",
            side_effect=RuntimeError("VM crashed"),
        ):
            result_str = _run_verify_direct(
                "C:\\e.exe", "C:\\d.sys", "svc", 90, "high")
        result = json.loads(result_str)
        assert result["passed"] is False
        assert "VM crashed" in result["error"]

    def test_calls_verify_directly_not_subprocess(self):
        """_run_verify_direct imports and calls verify(), no subprocess.run."""
        import inspect
        source = inspect.getsource(_run_verify_direct)
        assert "subprocess.run" not in source
        assert "from windows_exploit_dev.verify_exploit import verify" in source


# ===========================================================================
# MCP tool: compile_exploit
# ===========================================================================

class TestMCPCompileExploit:
    def test_missing_source_returns_error(self):
        result_str = run_async(compile_exploit("C:\\nonexistent\\exploit.c"))
        result = json.loads(result_str)
        assert result["success"] is False
        assert "not found" in result["compiler_output"].lower()

    def test_missing_vcvars_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
            f.write("int main() { return 0; }")
            src = f.name
        try:
            with mock.patch.dict(os.environ, {"PWNMCP_VCVARS_BAT": "C:\\no\\vcvars.bat"}):
                result_str = run_async(compile_exploit(src))
            result = json.loads(result_str)
            assert result["success"] is False
            assert "PWNMCP_VCVARS_BAT" in result["compiler_output"]
        finally:
            os.unlink(src)

    def test_no_vcvars_env_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
            f.write("int main() { return 0; }")
            src = f.name
        try:
            with mock.patch.dict(os.environ, {"PWNMCP_VCVARS_BAT": ""}, clear=False):
                result_str = run_async(compile_exploit(src))
            result = json.loads(result_str)
            assert result["success"] is False
        finally:
            os.unlink(src)


# ===========================================================================
# verify_exploit: dispatch, pipe isolation, no taskkill
# ===========================================================================

class TestVerifyDispatch:
    def test_verify_dispatches_to_high(self):
        from windows_exploit_dev import verify_exploit
        with mock.patch.object(verify_exploit, "verify_high_integrity",
                               return_value={"passed": True}) as m:
            result = verify_exploit.verify(Path("x.exe"), Path("d.sys"), "svc", integrity="high")
        m.assert_called_once()
        assert result["passed"] is True

    def test_verify_dispatches_to_medium(self):
        from windows_exploit_dev import verify_exploit
        with mock.patch.object(verify_exploit, "verify_medium_integrity",
                               return_value={"passed": False}) as m:
            result = verify_exploit.verify(Path("x.exe"), Path("d.sys"), "svc", integrity="medium")
        m.assert_called_once()
        assert result["passed"] is False

    def test_verify_default_is_medium(self):
        from windows_exploit_dev import verify_exploit
        with mock.patch.object(verify_exploit, "verify_medium_integrity",
                               return_value={"passed": False}) as m:
            verify_exploit.verify(Path("x.exe"), Path("d.sys"), "svc")
        m.assert_called_once()


class TestVerifyPipeIsolation:
    def test_verify_vm_uses_different_pipe(self):
        import re
        from windows_exploit_dev.vm.vmx_template import generate_vmx

        debug_vmx = generate_vmx("debug", Path("C:/d.vmdk"), "com_1", 4096, 2)
        verify_vmx = generate_vmx("verify", Path("C:/d.vmdk"), "com_verify", 4096, 2)

        debug_pipe = re.search(r'serial0\.fileName\s*=\s*"([^"]+)"', debug_vmx).group(1)
        verify_pipe = re.search(r'serial0\.fileName\s*=\s*"([^"]+)"', verify_vmx).group(1)

        assert debug_pipe != verify_pipe
        assert "com_verify" in verify_pipe

    def test_create_vm_instance_hardcodes_com_verify(self):
        import inspect
        from windows_exploit_dev.verify_exploit import create_vm_instance
        source = inspect.getsource(create_vm_instance)
        assert 'pipe_name="com_verify"' in source
        assert 'cfg.get("pipe_name"' not in source

    def test_no_taskkill_all_vmware(self):
        """create_vm_instance must NOT run taskkill on vmware-vmx.exe."""
        import inspect
        from windows_exploit_dev.verify_exploit import create_vm_instance
        source = inspect.getsource(create_vm_instance)
        # Check there's no subprocess call to taskkill (comments are fine)
        assert "subprocess.run([\"taskkill\"" not in source, (
            "taskkill kills ALL VMs including the debug VM — use vmrun stop instead"
        )


# ===========================================================================
# exploit_goal: constraints_section per integrity_mode
# ===========================================================================

class TestConstraintsSection:
    def test_high_mode_says_admin(self):
        text = exploit_goal.constraints_section(integrity_mode="high")
        assert "ADMIN USER (HIGH INTEGRITY)" in text
        assert "NON-ADMIN" not in text

    def test_high_mode_allows_admin_apis(self):
        text = exploit_goal.constraints_section(integrity_mode="high")
        assert "NtQuerySystemInformation" in text
        assert "EnumDeviceDrivers" in text
        assert "Admin-only APIs" not in text

    def test_medium_mode_says_non_admin(self):
        text = exploit_goal.constraints_section(integrity_mode="medium")
        assert "NON-ADMIN" in text
        assert "ADMIN USER (HIGH INTEGRITY)" not in text

    def test_medium_mode_forbids_admin_apis(self):
        text = exploit_goal.constraints_section(integrity_mode="medium")
        assert "Admin-only APIs" in text

    def test_both_mode_says_non_admin(self):
        text = exploit_goal.constraints_section(integrity_mode="both")
        assert "NON-ADMIN" in text

    def test_default_is_both(self):
        assert exploit_goal.constraints_section() == exploit_goal.constraints_section("both")


# ===========================================================================
# exploit_goal: verification_section per integrity_mode
# ===========================================================================

class TestVerificationSection:
    KW = {"iter_dir": "C:\\test", "driver_path": "C:\\drv.sys", "service_name": "svc"}

    def test_high_only_shows_high_tool(self):
        text = exploit_goal.verification_section(**self.KW, integrity_mode="high")
        assert "final_verification_high" in text
        assert "final_verification_medium" not in text
        assert "HIGH INTEGRITY ONLY" in text

    def test_medium_only_shows_medium_tool(self):
        text = exploit_goal.verification_section(**self.KW, integrity_mode="medium")
        assert "final_verification_medium" in text
        assert "final_verification_high" not in text
        assert "MEDIUM INTEGRITY ONLY" in text

    def test_both_shows_both_in_order(self):
        text = exploit_goal.verification_section(**self.KW, integrity_mode="both")
        assert "final_verification_high" in text
        assert "final_verification_medium" in text
        assert text.index("final_verification_high") < text.index("final_verification_medium")

    def test_default_is_both(self):
        assert (exploit_goal.verification_section(**self.KW) ==
                exploit_goal.verification_section(**self.KW, integrity_mode="both"))


# ===========================================================================
# agent_prompt: tool table visibility per integrity_mode
# ===========================================================================

class TestAgentPromptToolVisibility:
    BASE = {
        "driver_path": Path("C:/drv.sys"), "service_name": "svc",
        "context": "", "iteration": 1,
        "iteration_dir": Path("C:/iter"), "handoff_content": "test",
    }

    def test_high_mode_hides_medium_verification(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="high")
        assert "final_verification_high" in prompt
        assert "final_verification_medium" not in prompt

    def test_medium_mode_hides_high_verification(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="medium")
        assert "final_verification_medium" in prompt
        assert "final_verification_high" not in prompt

    def test_both_mode_shows_both(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="both")
        assert "final_verification_high" in prompt
        assert "final_verification_medium" in prompt

    def test_default_shows_both(self):
        prompt = build_analysis_prompt(**self.BASE)
        assert "final_verification_high" in prompt
        assert "final_verification_medium" in prompt

    def test_high_mode_constraints_in_prompt(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="high")
        assert "ADMIN USER (HIGH INTEGRITY)" in prompt
        assert "YOUR EXPLOIT MUST WORK AS A REGULAR (NON-ADMIN) USER" not in prompt

    def test_medium_mode_constraints_in_prompt(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="medium")
        assert "NON-ADMIN" in prompt
        assert "ADMIN USER (HIGH INTEGRITY)" not in prompt

    def test_high_mode_verification_section_in_prompt(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="high")
        assert "HIGH INTEGRITY ONLY" in prompt
        assert "MEDIUM INTEGRITY ONLY" not in prompt

    def test_medium_mode_verification_section_in_prompt(self):
        prompt = build_analysis_prompt(**self.BASE, integrity_mode="medium")
        assert "MEDIUM INTEGRITY ONLY" in prompt
        assert "HIGH INTEGRITY ONLY" not in prompt

    def test_common_tools_always_present(self):
        for mode in ("high", "medium", "both"):
            prompt = build_analysis_prompt(**self.BASE, integrity_mode=mode)
            for tool in ("windbg_command", "run_exploit", "break_execution",
                         "resume_and_wait", "recover_vm", "compile_exploit",
                         "rop_gadget_search"):
                assert tool in prompt, "%s missing in %s mode" % (tool, mode)


# ===========================================================================
# CLI arg parsing
# ===========================================================================

class TestCLIArgs:
    def _parse(self, *args):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("driver", nargs="?", default=None)
        parser.add_argument("--no-verify", action="store_true")
        grp = parser.add_mutually_exclusive_group()
        grp.add_argument("--high-integrity-only", action="store_true")
        grp.add_argument("--medium-integrity-only", action="store_true")
        return parser.parse_args(list(args))

    def test_high_flag(self):
        a = self._parse("--high-integrity-only")
        assert a.high_integrity_only and not a.medium_integrity_only

    def test_medium_flag(self):
        a = self._parse("--medium-integrity-only")
        assert a.medium_integrity_only and not a.high_integrity_only

    def test_no_flags(self):
        a = self._parse()
        assert not a.high_integrity_only and not a.medium_integrity_only

    def test_mutual_exclusivity(self):
        with pytest.raises(SystemExit):
            self._parse("--high-integrity-only", "--medium-integrity-only")

    def test_mode_resolution(self):
        for flag, exp in [("--high-integrity-only", "high"),
                          ("--medium-integrity-only", "medium")]:
            a = self._parse(flag)
            mode = "high" if a.high_integrity_only else (
                "medium" if a.medium_integrity_only else "both")
            assert mode == exp
        a = self._parse()
        assert ("high" if a.high_integrity_only else (
            "medium" if a.medium_integrity_only else "both")) == "both"


# ===========================================================================
# Phase 5 routing & hard stop
# ===========================================================================

class TestPhase5AndHardStop:
    def test_phase5_passes_integrity_to_verify(self):
        import inspect
        from windows_exploit_dev.pipeline import iteration_loop
        src = inspect.getsource(iteration_loop._run_single_iteration)
        assert "integrity=verify_integrity" in src

    def test_phase5_default_is_high(self):
        import inspect
        from windows_exploit_dev.pipeline import iteration_loop
        src = inspect.getsource(iteration_loop._run_single_iteration)
        assert 'else "high"' in src

    def test_loop_breaks_on_pass(self):
        import inspect
        from windows_exploit_dev.pipeline import iteration_loop
        src = inspect.getsource(iteration_loop.main)
        assert "if verification_passed" in src
        assert "break" in src
