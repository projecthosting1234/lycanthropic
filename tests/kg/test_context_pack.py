"""Tests for Stage 4: Context pack generation from knowledge graph.

Tests:
1. Context pack from seeded-only graph has primitives/protections, empty attempts
2. Token count under 4000
3. With simulated iterations, shows failed attempts and constraints
4. Truncation keeps high-priority items under budget
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
import yaml

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

BIODRV_INITIAL = Path(_PROJECT_ROOT) / "exploits_out" / "BioNTdrv" / "initial_information.md"


@pytest.fixture
def seeded_engagement(neo4j_driver, neo4j_config, neo4j_session):
    """Seed BioNTdrv data and return engagement_id. Cleanup after."""
    if not BIODRV_INITIAL.exists():
        pytest.skip("BioNTdrv initial_information.md not found")

    from windows_exploit_dev.kg.ingest.seed_from_initial import seed_from_initial

    eid = f"test-ctx-{uuid.uuid4().hex[:8]}"
    seed_from_initial(BIODRV_INITIAL, eid, neo4j_driver, neo4j_config["database"])
    yield eid
    neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
        eid=eid,
    ).consume()


# ── Test 1: Context pack from seeded-only graph ──


@pytest.mark.neo4j
def test_context_pack_seeded_only(neo4j_driver, neo4j_config, seeded_engagement):
    from windows_exploit_dev.pipeline.context_pack import generate_context_pack

    result = generate_context_pack(
        seeded_engagement, neo4j_driver, neo4j_config["database"],
    )

    # Valid YAML
    data = yaml.safe_load(result)
    assert "context_pack" in data
    cp = data["context_pack"]

    # Has primitives
    assert len(cp["primitives"]) >= 2
    prim_names = {p["name"] for p in cp["primitives"]}
    assert "arbitrary_write" in prim_names
    assert "physical_memory_map" in prim_names

    # Has protections
    assert len(cp["protections"]) >= 4
    prot_names = {p["name"] for p in cp["protections"]}
    assert "KASLR" in prot_names

    # No failed attempts yet
    assert cp["failed_attempts"] == [] or cp["failed_attempts"] is None


# ── Test 2: Token budget ──


@pytest.mark.neo4j
def test_context_pack_token_budget(neo4j_driver, neo4j_config, seeded_engagement):
    from windows_exploit_dev.pipeline.context_pack import generate_context_pack, _count_tokens

    result = generate_context_pack(
        seeded_engagement, neo4j_driver, neo4j_config["database"],
    )
    tokens = _count_tokens(result)
    assert tokens < 4000, f"Context pack is {tokens} tokens, exceeds budget"


# ── Test 3: With simulated iterations ──


@pytest.mark.neo4j
def test_context_pack_with_iterations(neo4j_driver, neo4j_config, neo4j_session, seeded_engagement):
    from windows_exploit_dev.pipeline.context_pack import generate_context_pack

    eid = seeded_engagement

    # Create some attempts
    for i, (name, reason) in enumerate([
        ("TokenSwap", "Token offset wrong for build 26100"),
        ("PreviousMode flip", "BSOD 0x1F9 on syscall return"),
        ("PPL clear", "Token DACL blocks access after PPL zeroed"),
    ]):
        neo4j_session.run(
            "MERGE (ap:Approach {name: $name, engagement_id: $eid})"
            "  ON CREATE SET ap.approach_id = $apid, ap.status = 'dead_end'"
            " CREATE (att:Attempt {"
            "  attempt_id: $attid, outcome: 'failure', verdict: 'dead_end',"
            "  failure_reason: $reason, engagement_id: $eid, iteration: $iter"
            "}) CREATE (att)-[:INSTANCE_OF]->(ap)",
            name=name, eid=eid,
            apid=str(uuid.uuid4()), attid=str(uuid.uuid4()),
            reason=reason, iter=i + 1,
        ).consume()

    # Create constraints
    for content in [
        "MmMapIoSpace cannot map cached RAM pages",
        "Non-admin cannot use EnumDeviceDrivers for KASLR bypass",
    ]:
        neo4j_session.run(
            "CREATE (c:Constraint {"
            "  constraint_id: $cid, content: $content,"
            "  engagement_id: $eid, discovered_iteration: 1"
            "})",
            cid=str(uuid.uuid4()), content=content, eid=eid,
        ).consume()

    result = generate_context_pack(eid, neo4j_driver, neo4j_config["database"])
    data = yaml.safe_load(result)
    cp = data["context_pack"]

    # Failed attempts present
    assert len(cp["failed_attempts"]) >= 3

    # Constraints present
    assert len(cp["constraints"]) >= 2


# ── Test 4: Truncation with large data ──


@pytest.mark.neo4j
def test_context_pack_truncation(neo4j_driver, neo4j_config, neo4j_session, seeded_engagement):
    from windows_exploit_dev.pipeline.context_pack import generate_context_pack, _count_tokens

    eid = seeded_engagement

    # Create 25 attempts
    for i in range(25):
        neo4j_session.run(
            "MERGE (ap:Approach {name: $name, engagement_id: $eid})"
            "  ON CREATE SET ap.approach_id = $apid, ap.status = 'dead_end'"
            " CREATE (att:Attempt {"
            "  attempt_id: $attid, outcome: 'failure', verdict: 'dead_end',"
            "  failure_reason: $reason, engagement_id: $eid, iteration: $iter"
            "}) CREATE (att)-[:INSTANCE_OF]->(ap)",
            name=f"approach_{i}", eid=eid,
            apid=str(uuid.uuid4()), attid=str(uuid.uuid4()),
            reason=f"Failed because of reason {i} with additional details about what went wrong " * 3,
            iter=i % 5 + 1,
        ).consume()

    # Create 12 constraints
    for i in range(12):
        neo4j_session.run(
            "CREATE (c:Constraint {"
            "  constraint_id: $cid, content: $content,"
            "  engagement_id: $eid, discovered_iteration: $iter"
            "})",
            cid=str(uuid.uuid4()),
            content=f"Constraint {i}: detailed limitation description explaining why approach {i} fails " * 2,
            eid=eid, iter=i % 5 + 1,
        ).consume()

    result = generate_context_pack(eid, neo4j_driver, neo4j_config["database"], token_budget=4000)
    tokens = _count_tokens(result)
    assert tokens <= 4000, f"Truncated context pack is {tokens} tokens"

    # High-priority sections still present
    data = yaml.safe_load(result)
    cp = data["context_pack"]
    assert len(cp["primitives"]) >= 2
    assert len(cp["protections"]) >= 4
