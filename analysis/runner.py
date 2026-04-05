#!/usr/bin/env python3
"""
Run vulnerability detectors on a target binary.

Usage:
    python -m analysis.runner driver.sys --arbitrary-write
    python -m analysis.runner driver.sys --heap-overflow --stack-overflow
    python -m analysis.runner driver.sys --all

Detectors are in analysis/vulnerabilities/. Each is invoked by name.
Target must be loadable in IDA (run from IDA or idat64 -A -S"python -c 'import analysis.runner; analysis.runner.main()'").
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
import os

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _ensure_project_root() -> None:
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    import os

    os.chdir(_PROJECT_ROOT)


# Map CLI flag -> (vulnerabilities module name, display name)
_DETECTORS = {
    "arbitrary-write": ("arbitrary_write", "Arbitrary Write"),
    "heap-overflow": ("heap_overflow", "Heap Overflow"),
    "stack-overflow": ("stack_overflow", "Stack Overflow"),
    "int-overflow": ("int_overflow", "Integer Overflow"),
    "use-after-free": ("use_after_free", "Use After Free"),
    "missing-validation": ("missing_validation", "Missing Validation"),
}


def _open_target(target: Path, *, new_idb: bool = False) -> None:
    """Open target in IDA. Requires idapro / IDA environment."""
    _ensure_project_root()
    from analysis.common import ida_wrapper

    db_path = str(target.resolve())
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    if new_idb:
        # Delete any stale IDA databases/aux files for this target before opening.
        base = Path(target.resolve())
        for ext in (".id0", ".id1", ".id2", ".idb", ".i64", ".nam", ".til", ".tnc"):
            try:
                stale = db_path + ext
               # print(f"Deleting stale IDA database: {stale} db_path={db_path}")
                os.remove(stale)
            except Exception:
                # Best-effort cleanup; failures will show up when opening DB.
             #   print(f"[!] Failed to delete stale IDA database: {stale}", file=sys.stderr)
                continue

    ida_wrapper.open_ida_db(db_path)
    ida_wrapper.init_hexrays()


def _run_detector(
    module_name: str,
    target: Path,
    findings_dir: Path,
    config_path: Path | None,
) -> list:
    """Import and run a detector's run_detector(target, findings_dir, config_path)."""
    mod = __import__(f"analysis.vulnerabilities.{module_name}", fromlist=["run_detector"])
    run_fn = getattr(mod, "run_detector", None)
    if run_fn is None:
        print(f"[!] {module_name}: no run_detector found", file=sys.stderr)
        return []
    return run_fn(target, findings_dir, config_path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run vulnerability detectors on a target binary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Target binary (or IDA database path)",
    )
    parser.add_argument(
        "--arbitrary-write",
        action="store_true",
        help="Run arbitrary write detector",
    )
    parser.add_argument(
        "--heap-overflow",
        action="store_true",
        help="Run heap overflow detector",
    )
    parser.add_argument(
        "--stack-overflow",
        action="store_true",
        help="Run stack overflow detector",
    )
    parser.add_argument(
        "--int-overflow",
        action="store_true",
        help="Run integer overflow detector",
    )
    parser.add_argument(
        "--use-after-free",
        action="store_true",
        help="Run use-after-free detector",
    )
    parser.add_argument(
        "--missing-validation",
        action="store_true",
        help="Run missing validation detector",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all detectors",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_PROJECT_ROOT / "config.json",
        help="Config path (default: config.json)",
    )
    parser.add_argument(
        "--emit-findings",
        type=Path,
        default=_PROJECT_ROOT / "findings_out",
        help="Findings output directory (default: findings_out)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Skip opening target (use when IDA already has database loaded)",
    )
    parser.add_argument(
        "--new-idb",
        action="store_true",
        help="Delete existing IDA DB files for target before opening",
    )
    args = parser.parse_args()

    selected = [
        k
        for k in _DETECTORS
        if (args.all or getattr(args, k.replace("-", "_"), False))
    ]
    if not selected:
        parser.error("Specify at least one detector (e.g. --arbitrary-write) or --all")

    _ensure_project_root()

    if not args.no_open:
        try:
            _open_target(args.target, new_idb=args.new_idb)
        except Exception as e:
            print(f"[!] Failed to open target: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 1

    findings_dir = args.emit_findings.resolve()
    findings_dir.mkdir(parents=True, exist_ok=True)
    config_path = args.config if args.config.exists() else None

    all_results = []
    for key in selected:
        module_name, display = _DETECTORS[key]
        print(f"[*] Running {display} ({module_name})...")
        try:
            results = _run_detector(
                module_name,
                args.target,
                findings_dir,
                config_path,
            )
            all_results.extend(results)
            print(f"    -> {len(results)} finding(s)")
        except Exception as e:
            print(f"[!] {display} failed: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc()

    print(f"\n[*] Done. Total findings: {len(all_results)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
