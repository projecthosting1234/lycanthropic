"""Tests for Stage 6: KG projections and cutover.

Tests:
1. Exploit state report from graph matches standard format
2. Handoff report from graph has required sections
3. Reconciliation records dead ends + artifacts
4. Agent prompt contains zero flat-file content for iteration 2+
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


@pytest.fixture
def proj_engagement(neo4j_driver, neo4j_config, neo4j_session):
    """Create an engagement with dead ends and attempts for projection tests."""
    eid = f"test-proj-{uuid.uuid4().hex[:8]}"
    db = neo4j_config["database"]

    # Create engagement
    neo4j_session.run(
        "CREATE (e:Engagement {engagement_id: $eid, driver_name: 'TestDriver', status: 'active'})",
        eid=eid,
    ).consume()

    # Create dead-end approaches + attempts
    for name, reason, evidence in [
        ("TokenSwap", "Token offset wrong", "BSOD 0x50"),
        ("PreviousMode flip", "Bugcheck on syscall return", "0x000001F9"),
        ("PPL clear", "DACL blocks access after PPL zeroed", "OpenProcessToken failed: 5"),
    ]:
        neo4j_session.run(
            "MERGE (ap:Approach {name: $name, engagement_id: $eid})"
            "  ON CREATE SET ap.approach_id = $apid, ap.status = 'dead_end', ap.created_at = '2026-01-01'"
            " CREATE (att:Attempt {"
            "  attempt_id: $attid, outcome: 'failure', verdict: 'dead_end',"
            "  failure_reason: $reason, evidence_excerpt: $evidence,"
            "  engagement_id: $eid, iteration: 1, created_at: '2026-01-01', created_by: 'pipeline'"
            "}) CREATE (att)-[:INSTANCE_OF]->(ap)",
            name=name, eid=eid, apid=str(uuid.uuid4()), attid=str(uuid.uuid4()),
            reason=reason, evidence=evidence,
        ).consume()

    # Create a constraint
    neo4j_session.run(
        "CREATE (c:Constraint {constraint_id: $cid, content: 'Cannot map cached RAM', "
        "  engagement_id: $eid, discovered_iteration: 1})",
        cid=str(uuid.uuid4()), eid=eid,
    ).consume()

    yield eid

    neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
        eid=eid,
    ).consume()


# ── Test 1: EXPLOIT_STATE report from graph ──


@pytest.mark.neo4j
def test_exploit_state_report(neo4j_driver, neo4j_config, proj_engagement):
    from windows_exploit_dev.kg.projections.exploit_state_report import (
        generate_exploit_state_report,
    )

    report = generate_exploit_state_report(
        proj_engagement, neo4j_driver, neo4j_config["database"],
    )

    # Has standard header
    assert "# Exploit State" in report
    assert "## Dead Ends" in report

    # Has all 3 dead ends
    assert "**TokenSwap**" in report
    assert "**PreviousMode flip**" in report
    assert "**PPL clear**" in report

    # Each has reason text
    assert "Token offset wrong" in report
    assert "BSOD 0x50" in report


# ── Test 2: Handoff report from graph ──


@pytest.mark.neo4j
def test_handoff_report(neo4j_driver, neo4j_config, proj_engagement):
    from windows_exploit_dev.kg.projections.handoff_report import generate_handoff_report

    report = generate_handoff_report(
        proj_engagement, 1, neo4j_driver, neo4j_config["database"],
    )

    # Has iteration header
    assert "Iteration 1 Handoff" in report

    # Has strategy section (from attempts)
    assert "Exploit Strategy" in report or "What Failed" in report

    # Has dead ends section with markers
    assert "DEAD_ENDS_START" in report
    assert "DEAD_ENDS_END" in report
    assert "**TokenSwap**" in report


# ── Test 3: Reconciliation records dead ends + artifacts ──


@pytest.mark.neo4j
def test_reconcile_handoff(neo4j_driver, neo4j_config, neo4j_session):
    from windows_exploit_dev.kg.reconciliation import reconcile_handoff

    eid = f"test-recon-{uuid.uuid4().hex[:8]}"

    sample_handoff = (
        "# Iteration 1 Handoff\n\n"
        "## DEAD ENDS\n\n"
        "<!-- DEAD_ENDS_START -->\n"
        "- **HeapSpray**: Heap exhaustion before spray completes. Evidence: OOM at 0x4000 allocations\n"
        "- **VTableHijack**: CFG blocks indirect call. Evidence: STATUS_STACK_BUFFER_OVERRUN\n"
        "<!-- DEAD_ENDS_END -->\n\n"
        "## Verification\n\n**FAILED**: BSOD 0x50\n"
    )

    try:
        counts = reconcile_handoff(
            sample_handoff, eid, 1, neo4j_driver, neo4j_config["database"],
        )
        assert counts["dead_ends"] == 2

        # Verify nodes created
        approaches = neo4j_session.run(
            "MATCH (ap:Approach {engagement_id: $eid}) RETURN ap.name AS name, ap.status AS status",
            eid=eid,
        ).data()
        assert len(approaches) == 2
        names = {a["name"] for a in approaches}
        assert "HeapSpray" in names
        assert "VTableHijack" in names
        for a in approaches:
            assert a["status"] == "dead_end"

        # Verify attempts linked
        attempts = neo4j_session.run(
            "MATCH (att:Attempt {engagement_id: $eid})-[:INSTANCE_OF]->(ap:Approach) "
            "RETURN count(att) AS c",
            eid=eid,
        ).data()
        assert attempts[0]["c"] == 2

        # Verify verification recorded
        assert counts["verifications"] == 1
    finally:
        neo4j_session.run(
            "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
            eid=eid,
        ).consume()


# ── Test 4: Agent prompt contains zero flat-file content for iter 2+ ──


@pytest.mark.neo4j
def test_prompt_no_flat_files_iter2():
    from windows_exploit_dev.pipeline.agent_prompt import build_analysis_prompt

    prompt = build_analysis_prompt(
        driver_path=None,
        service_name="test_svc",
        context="",
        iteration=2,
        handoff_content=None,  # cutover: no handoff for iter 2+
        initial_info="Initial vulnerability analysis here.",
        context_pack_yaml="primitives:\n- name: arb_write\n  verified: true\n",
    )

    # Context pack IS present
    assert "Knowledge Graph Context Pack" in prompt
    assert "arb_write" in prompt

    # Flat-file sections are NOT present
    assert "Previous Iteration Handoff" not in prompt
    assert "Cumulative Exploit State" not in prompt

    # Initial info IS still present
    assert "Initial Information" in prompt
    assert "Initial vulnerability analysis here" in prompt


# ── Test 5: Prompt for iteration 1 still uses handoff_content ──


@pytest.mark.neo4j
def test_prompt_iter1_uses_handoff():
    from windows_exploit_dev.pipeline.agent_prompt import build_analysis_prompt

    prompt = build_analysis_prompt(
        driver_path=None,
        service_name="test_svc",
        context="",
        iteration=1,
        handoff_content="Initial info as handoff for iter 1.",
    )

    assert "Initial Information" in prompt
    assert "Initial info as handoff for iter 1" in prompt
    # No context pack for iteration 1
    assert "Knowledge Graph Context Pack" not in prompt
