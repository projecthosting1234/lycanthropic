#!/usr/bin/env python3
"""
Wrapper script for running analysis passes.

Calls run_pass1_pipeline and run_pass2_pipeline directly (no subprocess).
Use --pass1 and/or --pass2 to choose which pass to run.

Usage:
    python harness/run_all_analysis_passes.py --pass1 driver.sys
    python harness/run_all_analysis_passes.py --pass2 findings_out/driver.sys
    python harness/run_all_analysis_passes.py --pass1 --pass2 driver.sys
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

def _ensure_project_root():
    """Ensure project root is on sys.path and cwd for imports."""
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    os.chdir(_PROJECT_ROOT)


def _build_driver_stack_config(target: str, args) -> object | None:
    """Build cross-driver config from args (driver-stack YAML or lower-driver list)."""
    if args.driver_stack:
        from analysis.cross_driver_config import load_driver_stack_config
        return load_driver_stack_config(args.driver_stack)
    if args.lower_driver:
        from analysis.cross_driver_config import build_config_from_cli
        return build_config_from_cli(target, args.lower_driver)
    return None


def run_pass1(driver_path: str, args) -> bool:
    """Run Pass 1 analysis by calling run_pass1_pipeline directly."""
    _ensure_project_root()
    from analysis.passes.pass1 import run_pass1_pipeline

    print(f"[*] Running Pass 1 analysis on {driver_path}")

    ds_config = _build_driver_stack_config(driver_path, args)
    if ds_config is not None:
        print(f"[*] Driver stack: {len(ds_config.lower_drivers)} lower driver(s)")

    try:

        from harness.win_symbols_builder import build_windows_symbols
        pre_smt_callbacks = [build_windows_symbols]
        
        if args.dashboard:
            from dashboard.new import run_with_dashboard
            run_with_dashboard(
                driver_path,
                pipeline_fn=run_pass1_pipeline,
                pipeline_name="pass1",
                top_n=args.top,
                port=args.port,
                no_browser=args.no_browser,
                emit_dir=args.emit_findings,
                no_prune=args.no_prune,
                driver_stack_config=ds_config,
                timeout_ms=args.timeout,
                no_repair=args.no_repair,
                verbose=args.verbose,
                pipeline_stage=args.pipeline_stage,
                pre_smt_callbacks=pre_smt_callbacks,
            )
        else:
            run_pass1_pipeline(
                driver_path,
                top_n=args.top,
                emit_dir=args.emit_findings,
                no_prune=args.no_prune,
                driver_stack_config=ds_config,
                timeout_ms=args.timeout,
                no_repair=args.no_repair,
                verbose=args.verbose,
                pipeline_stage=args.pipeline_stage,
                pre_smt_callbacks=pre_smt_callbacks,
            )
        print("[*] Pass 1 completed successfully")
        return True
    except Exception as e:
        print(f"[!] Pass 1 failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_pass2(findings_dir: str | Path, args) -> bool:
    """Run Pass 2 analysis by calling run_pass2_pipeline directly."""
    _ensure_project_root()
    from analysis.passes.pass2 import run_pass2_pipeline

    print(f"[*] Running Pass 2 analysis on {findings_dir}")

    try:
        run_pass2_pipeline(
            findings_dir,
            max_depth=args.max_depth,
            timeout_ms=args.timeout,
            verbose=args.verbose,
            pipeline_stage=args.pipeline_stage,
        )
        print("[*] Pass 2 completed successfully")
        return True
    except Exception as e:
        print(f"[!] Pass 2 failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Run analysis passes via direct pipeline calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python harness/run_all_analysis_passes.py --pass1 driver.sys\n"
            "  python harness/run_all_analysis_passes.py --pass2 findings_out/driver.sys\n"
            "  python harness/run_all_analysis_passes.py --pass1 --pass2 driver.sys\n"
        ),
    )
    parser.add_argument("--pass1", action="store_true", help="Run Pass 1 (arbitrary write + missing validation)")
    parser.add_argument("--pass2", action="store_true", help="Run Pass 2 (heap overflow + integer overflow)")
    parser.add_argument("target", help="Driver binary for Pass 1, or findings directory for Pass 2")

    parser.add_argument("--dashboard", action="store_true", help="Launch dashboard in browser (Pass 1)")
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    parser.add_argument("--emit-findings", metavar="DIR", default="findings_out", help="Findings output dir (default: findings_out)")
    parser.add_argument("--timeout", type=int, default=30000, help="SMT timeout ms (default: 30000)")
    parser.add_argument("--no-repair", action="store_true", help="Disable constraint repair")
    parser.add_argument("--no-prune", action="store_true", help="Disable reachability pruning")
    parser.add_argument("--top", type=int, default=10, help="Top N sinks (default: 10)")
    parser.add_argument("--driver-stack", metavar="YAML", default=None, help="Driver stack config YAML")
    parser.add_argument("--lower-driver", metavar="PATH", action="append", default=None, help="Lower driver binary (repeatable)")
    parser.add_argument(
        "--pipeline-stage",
        metavar="STAGE",
        default=None,
        choices=["tracing", "smt", "vulnerability"],
        help="Run only one Pass 1 stage: tracing, smt, or vulnerability. If omitted, run all.",
    )
    parser.add_argument("--max-depth", type=int, default=5, help="Pass 2 max depth (default: 5)")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")

    args = parser.parse_args()

    if not args.pass1 and not args.pass2:
        parser.error("Specify at least one of --pass1 or --pass2")

    success = True

    if args.pass1:
        target_path = Path(args.target)
        if not target_path.exists():
            print(f"[!] Target not found: {args.target}", file=sys.stderr)
            sys.exit(1)
        if not run_pass1(args.target, args):
            success = False
            if args.pass2:
                print("[!] Skipping Pass 2 after Pass 1 failure")
                return 1

    if args.pass2:
        findings_dir = args.target
        if args.pass1:
            findings_dir = Path(args.emit_findings) / Path(args.target).name
        if not run_pass2(findings_dir, args):
            success = False

    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    except SystemExit:
        raise
    except BaseException as e:
        import traceback
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
