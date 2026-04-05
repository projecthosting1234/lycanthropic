"""Tests for Stage 7: Graph validation script.

Tests:
1. Validation passes on clean, well-formed graph
2. Catches orphan Attempt (no INSTANCE_OF link)
3. Catches orphan Constraint (no DERIVED_FROM link)
4. Catches missing engagement_id
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


@pytest.fixture
def val_engagement(neo4j_driver, neo4j_config, neo4j_session):
    """Create a clean engagement with well-formed data for validation."""
    eid = f"test-val-{uuid.uuid4().hex[:8]}"

    # Clean global orphan evidence from prior test runs (Check 5 is global)
    neo4j_session.run(
        "MATCH (e:Evidence) "
        "WHERE NOT EXISTS { MATCH (:Observation)-[:SUPPORTED_BY]->(e) } "
        "DELETE e",
    ).consume()

    # Engagement
    neo4j_session.run(
        "CREATE (e:Engagement {engagement_id: $eid, driver_name: 'TestDrv', status: 'active'})",
        eid=eid,
    ).consume()

    # Approach + Attempt (properly linked)
    neo4j_session.run(
        "MERGE (ap:Approach {name: 'TokenSwap', engagement_id: $eid})"
        "  ON CREATE SET ap.approach_id = $apid, ap.status = 'dead_end'"
        " CREATE (att:Attempt {"
        "  attempt_id: $attid, outcome: 'failure', verdict: 'dead_end',"
        "  engagement_id: $eid, iteration: 1"
        "}) CREATE (att)-[:INSTANCE_OF]->(ap)",
        eid=eid, apid=str(uuid.uuid4()), attid=str(uuid.uuid4()),
    ).consume()

    # Observation + Constraint (properly linked)
    obs_id = str(uuid.uuid4())
    neo4j_session.run(
        "CREATE (o:Observation {"
        "  observation_id: $oid, type: 'value', status: 'active',"
        "  summary: 'test obs', engagement_id: $eid"
        "})",
        oid=obs_id, eid=eid,
    ).consume()
    neo4j_session.run(
        "MATCH (o:Observation {observation_id: $oid})"
        " CREATE (c:Constraint {"
        "  constraint_id: $cid, content: 'test constraint',"
        "  engagement_id: $eid, discovered_iteration: 1"
        "}) CREATE (c)-[:DERIVED_FROM]->(o)",
        oid=obs_id, cid=str(uuid.uuid4()), eid=eid,
    ).consume()

    # Protection
    neo4j_session.run(
        "CREATE (p:Protection {"
        "  protection_id: $pid, name: 'KASLR',"
        "  bypass_status: 'untested', engagement_id: $eid"
        "})",
        pid=str(uuid.uuid4()), eid=eid,
    ).consume()

    yield eid

    neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
        eid=eid,
    ).consume()


# ── Test 1: Clean graph passes all checks ──


@pytest.mark.neo4j
def test_validation_passes_clean_graph(neo4j_driver, neo4j_config, val_engagement):
    from windows_exploit_dev.kg.validate_graph import validate_graph

    results = validate_graph(val_engagement, neo4j_driver, neo4j_config["database"])

    for r in results:
        assert r["status"] == "pass", f"Check {r['check']} failed: {r['details']}"


# ── Test 2: Catches orphan Attempt ──


@pytest.mark.neo4j
def test_catches_orphan_attempt(neo4j_driver, neo4j_config, neo4j_session, val_engagement):
    from windows_exploit_dev.kg.validate_graph import validate_graph

    # Create an Attempt WITHOUT INSTANCE_OF link
    neo4j_session.run(
        "CREATE (att:Attempt {"
        "  attempt_id: $attid, outcome: 'failure',"
        "  engagement_id: $eid, iteration: 1"
        "})",
        attid=str(uuid.uuid4()), eid=val_engagement,
    ).consume()

    results = validate_graph(val_engagement, neo4j_driver, neo4j_config["database"])
    orphan_check = next(r for r in results if r["check"] == "orphan_attempts")
    assert orphan_check["status"] == "fail"
    assert orphan_check["count"] >= 1


# ── Test 3: Catches orphan Constraint ──


@pytest.mark.neo4j
def test_catches_orphan_constraint(neo4j_driver, neo4j_config, neo4j_session, val_engagement):
    from windows_exploit_dev.kg.validate_graph import validate_graph

    # Create a Constraint WITHOUT DERIVED_FROM link
    neo4j_session.run(
        "CREATE (c:Constraint {"
        "  constraint_id: $cid, content: 'orphan constraint',"
        "  engagement_id: $eid"
        "})",
        cid=str(uuid.uuid4()), eid=val_engagement,
    ).consume()

    results = validate_graph(val_engagement, neo4j_driver, neo4j_config["database"])
    orphan_check = next(r for r in results if r["check"] == "orphan_constraints")
    assert orphan_check["status"] == "fail"
    assert orphan_check["count"] >= 1


# ── Test 4: Catches missing engagement_id ──


@pytest.mark.neo4j
def test_catches_missing_engagement_id(neo4j_driver, neo4j_config, neo4j_session, val_engagement):
    from windows_exploit_dev.kg.validate_graph import validate_graph

    # Create a node WITHOUT engagement_id
    neo4j_session.run(
        "CREATE (ap:Approach {name: 'NoEid', approach_id: $apid})",
        apid=str(uuid.uuid4()),
    ).consume()

    results = validate_graph(val_engagement, neo4j_driver, neo4j_config["database"])
    missing_check = next(r for r in results if r["check"] == "missing_engagement_id")
    assert missing_check["status"] == "fail"
    assert missing_check["count"] >= 1

    # Cleanup the no-engagement node
    neo4j_session.run(
        "MATCH (ap:Approach {name: 'NoEid'}) DELETE ap",
    ).consume()
