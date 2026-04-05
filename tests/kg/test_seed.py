"""Tests for Stage 4: KG seeding from initial_information.md and EXPLOIT_STATE.md.

Tests:
1. Seed creates expected node counts with correct properties
2. Seed is idempotent (running twice produces no duplicates)
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

BIODRV_INITIAL = Path(_PROJECT_ROOT) / "exploits_out" / "BioNTdrv" / "initial_information.md"
BIODRV_STATE = Path(_PROJECT_ROOT) / "exploits_out" / "BioNTdrv" / "EXPLOIT_STATE.md"


@pytest.fixture
def seed_engagement_id():
    return f"test-seed-{uuid.uuid4().hex[:8]}"


@pytest.fixture(autouse=True)
def cleanup_seed_data(neo4j_session, seed_engagement_id):
    yield
    neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
        eid=seed_engagement_id,
    ).consume()


def _count_by_label(neo4j_session, eid: str) -> dict:
    records = neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid "
        "RETURN labels(n)[0] AS label, count(n) AS cnt",
        eid=eid,
    ).data()
    return {r["label"]: r["cnt"] for r in records}


# ── Test 1: Seed creates expected nodes ──


@pytest.mark.neo4j
def test_seed_creates_expected_nodes(neo4j_driver, neo4j_config, neo4j_session, seed_engagement_id):
    if not BIODRV_INITIAL.exists():
        pytest.skip("BioNTdrv initial_information.md not found")

    from windows_exploit_dev.kg.ingest.seed_from_initial import seed_from_initial

    counts = seed_from_initial(
        BIODRV_INITIAL,
        seed_engagement_id,
        neo4j_driver,
        neo4j_config["database"],
    )

    # Verify returned counts
    assert counts["Engagement"] == 1
    assert counts["Driver"] == 1
    assert counts["Vulnerability"] == 2  # Finding 0: MmMapIoSpace, Finding 1: memmove
    assert counts["Primitive"] == 2      # physical_memory_map, arbitrary_write
    assert counts["Protection"] >= 4     # KASLR, SMEP, kCFG, HVCI + inferred
    assert counts["Artifact"] == 1

    # Verify in graph
    db_counts = _count_by_label(neo4j_session, seed_engagement_id)
    assert db_counts.get("Engagement", 0) == 1
    assert db_counts.get("Driver", 0) == 1
    assert db_counts.get("Vulnerability", 0) == 2
    assert db_counts.get("Primitive", 0) == 2
    assert db_counts.get("Protection", 0) >= 4

    # Spot-check property values
    drv = neo4j_session.run(
        "MATCH (d:Driver {engagement_id: $eid}) RETURN d",
        eid=seed_engagement_id,
    ).data()
    assert len(drv) == 1
    assert drv[0]["d"]["name"] == "BioNTdrv.sys"

    prims = neo4j_session.run(
        "MATCH (p:Primitive {engagement_id: $eid}) RETURN p.name AS name, p.type AS type "
        "ORDER BY p.name",
        eid=seed_engagement_id,
    ).data()
    prim_names = {p["name"] for p in prims}
    assert "arbitrary_write" in prim_names
    assert "physical_memory_map" in prim_names

    # Verify relationships exist
    rels = neo4j_session.run(
        "MATCH (eng:Engagement {engagement_id: $eid})-[:TARGETS]->(d:Driver)"
        "-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:YIELDS]->(p:Primitive) "
        "RETURN count(*) AS c",
        eid=seed_engagement_id,
    ).data()
    assert rels[0]["c"] >= 2


# ── Test 2: Seed is idempotent ──


@pytest.mark.neo4j
def test_seed_is_idempotent(neo4j_driver, neo4j_config, neo4j_session, seed_engagement_id):
    if not BIODRV_INITIAL.exists():
        pytest.skip("BioNTdrv initial_information.md not found")

    from windows_exploit_dev.kg.ingest.seed_from_initial import seed_from_initial

    # First seed
    counts1 = seed_from_initial(
        BIODRV_INITIAL, seed_engagement_id, neo4j_driver, neo4j_config["database"],
    )
    db_counts1 = _count_by_label(neo4j_session, seed_engagement_id)

    # Second seed — same engagement
    counts2 = seed_from_initial(
        BIODRV_INITIAL, seed_engagement_id, neo4j_driver, neo4j_config["database"],
    )
    db_counts2 = _count_by_label(neo4j_session, seed_engagement_id)

    # Counts should be identical (no duplicates)
    assert db_counts1 == db_counts2


# ── Test 3: EXPLOIT_STATE.md seeding ──


@pytest.mark.neo4j
def test_seed_exploit_state(neo4j_driver, neo4j_config, neo4j_session, seed_engagement_id):
    if not BIODRV_STATE.exists():
        pytest.skip("BioNTdrv EXPLOIT_STATE.md not found")

    from windows_exploit_dev.kg.ingest.seed_from_exploit_state import seed_from_exploit_state

    counts = seed_from_exploit_state(
        BIODRV_STATE, seed_engagement_id, neo4j_driver, neo4j_config["database"],
    )

    assert counts["Approach"] >= 5   # multiple dead ends in the file
    assert counts["Attempt"] >= 5

    # Verify all approaches are dead_end status
    approaches = neo4j_session.run(
        "MATCH (ap:Approach {engagement_id: $eid}) RETURN ap.status AS status",
        eid=seed_engagement_id,
    ).data()
    for ap in approaches:
        assert ap["status"] == "dead_end"

    # Verify INSTANCE_OF relationships
    rels = neo4j_session.run(
        "MATCH (att:Attempt {engagement_id: $eid})-[:INSTANCE_OF]->(ap:Approach) "
        "RETURN count(att) AS c",
        eid=seed_engagement_id,
    ).data()
    assert rels[0]["c"] >= 5

    # Idempotency: run again, no duplicates
    counts2 = seed_from_exploit_state(
        BIODRV_STATE, seed_engagement_id, neo4j_driver, neo4j_config["database"],
    )
    approach_count = neo4j_session.run(
        "MATCH (ap:Approach {engagement_id: $eid}) RETURN count(ap) AS c",
        eid=seed_engagement_id,
    ).data()[0]["c"]
    assert approach_count == counts["Approach"]
