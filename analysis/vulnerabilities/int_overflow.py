from __future__ import annotations

from pathlib import Path

from analysis.vulnerabilities import stub_disabled_detector


def run_detector(
    target: Path,
    findings_dir: Path,
    config_path: Path | None,
) -> list[dict]:
    """Entry point for runner: run int-overflow detector."""
    return stub_disabled_detector("int_overflow")


def run(
    variables: list[object],
    findings_dir: str | Path,
    config_path: str | None = None,
) -> list[dict]:
    return stub_disabled_detector("int_overflow")
