"""End-to-end tests for Stage 7: provenance chain and token budget stability.

Tests:
1. Full provenance chain is traceable from Constraint to Artifact
2. Context pack token budget stays under 4000 across simulated iterations
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


# ── Test 1: Provenance chain complete ──


@pytest.mark.neo4j
def test_provenance_chain_complete(neo4j_driver, neo4j_config, neo4j_session):
    """Create full provenance chain and verify every link is traceable."""
    eid = f"test-prov-{uuid.uuid4().hex[:8]}"

    try:
        # Create Artifact (pointing to a real file)
        artifact_uri = str(BIODRV_INITIAL.resolve()) if BIODRV_INITIAL.exists() else "file:///test.md"
        neo4j_session.run(
            "CREATE (a:Artifact {"
            "  artifact_id: $aid, uri: $uri, kind: 'log',"
            "  engagement_id: $eid"
            "})",
            aid=str(uuid.uuid4()), uri=artifact_uri, eid=eid,
        ).consume()

        # Create Evidence linked to Artifact
        ev_id = str(uuid.uuid4())
        neo4j_session.run(
            "MATCH (a:Artifact {engagement_id: $eid})"
            " CREATE (e:Evidence {"
            "  evidence_id: $evid, locator_type: 'line_range',"
            "  excerpt: 'MmMapIoSpace at 0x160a0', confidence: 'high'"
            "}) CREATE (e)-[:FROM_ARTIFACT]->(a)",
            evid=ev_id, eid=eid,
        ).consume()

        # Create Observation linked to Evidence
        obs_id = str(uuid.uuid4())
        neo4j_session.run(
            "MATCH (e:Evidence {evidence_id: $evid})"
            " CREATE (o:Observation {"
            "  observation_id: $oid, type: 'value', status: 'active',"
            "  summary: 'PhysAddr limited to 32-bit', engagement_id: $eid"
            "}) CREATE (o)-[:SUPPORTED_BY]->(e)",
            oid=obs_id, evid=ev_id, eid=eid,
        ).consume()

        # Create Constraint linked to Observation
        cid = str(uuid.uuid4())
        neo4j_session.run(
            "MATCH (o:Observation {observation_id: $oid})"
            " CREATE (c:Constraint {"
            "  constraint_id: $cid, content: 'PhysAddr < 4GB (32-bit only)',"
            "  verification_method: 'confirmed via register dump',"
            "  engagement_id: $eid, discovered_iteration: 1"
            "}) CREATE (c)-[:DERIVED_FROM]->(o)",
            cid=cid, oid=obs_id, eid=eid,
        ).consume()

        # Trace the full chain: Constraint → Observation → Evidence → Artifact
        chain = neo4j_session.run(
            "MATCH (c:Constraint {constraint_id: $cid})"
            "-[:DERIVED_FROM]->(o:Observation)"
            "-[:SUPPORTED_BY]->(e:Evidence)"
            "-[:FROM_ARTIFACT]->(a:Artifact) "
            "RETURN c.content AS constraint, o.summary AS observation, "
            "  e.excerpt AS evidence, a.uri AS artifact_uri",
            cid=cid,
        ).data()

        assert len(chain) == 1, f"Expected 1 chain, got {len(chain)}"
        row = chain[0]
        assert row["constraint"] == "PhysAddr < 4GB (32-bit only)"
        assert row["observation"] == "PhysAddr limited to 32-bit"
        assert row["evidence"] == "MmMapIoSpace at 0x160a0"
        assert row["artifact_uri"] == artifact_uri

        # Verify artifact URI points to a real file (if using BioNTdrv)
        if BIODRV_INITIAL.exists():
            assert Path(row["artifact_uri"]).exists(), \
                f"Artifact URI does not exist: {row['artifact_uri']}"

    finally:
        neo4j_session.run(
            "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
            eid=eid,
        ).consume()
        # Clean up Evidence nodes (no engagement_id)
        neo4j_session.run(
            "MATCH (e:Evidence) WHERE NOT EXISTS { MATCH ()-[]->(e) } "
            "AND NOT EXISTS { MATCH (e)-[]->() } DELETE e",
        ).consume()


# ── Test 2: Context pack token budget stable across iterations ──


@pytest.mark.neo4j
def test_context_pack_token_budget_stable(neo4j_driver, neo4j_config, neo4j_session):
    """Simulate 5 iterations of data and verify context pack stays under 4000 tokens."""
    if not BIODRV_INITIAL.exists():
        pytest.skip("BioNTdrv initial_information.md not found")

    from windows_exploit_dev.kg.ingest.seed_from_initial import seed_from_initial
    from windows_exploit_dev.pipeline.context_pack import generate_context_pack, _count_tokens

    eid = f"test-budget-{uuid.uuid4().hex[:8]}"

    try:
        # Seed initial data
        seed_from_initial(BIODRV_INITIAL, eid, neo4j_driver, neo4j_config["database"])

        token_counts = []

        # Simulate 5 iterations of growing data
        for iteration in range(1, 6):
            # Add attempts for this iteration
            for j in range(3):
                neo4j_session.run(
                    "MERGE (ap:Approach {name: $name, engagement_id: $eid})"
                    "  ON CREATE SET ap.approach_id = $apid, ap.status = 'dead_end'"
                    " CREATE (att:Attempt {"
                    "  attempt_id: $attid, outcome: 'failure', verdict: 'dead_end',"
                    "  failure_reason: $reason, engagement_id: $eid, iteration: $iter,"
                    "  created_at: $now"
                    "}) CREATE (att)-[:INSTANCE_OF]->(ap)",
                    name=f"approach_i{iteration}_j{j}",
                    eid=eid, apid=str(uuid.uuid4()), attid=str(uuid.uuid4()),
                    reason=f"Failed in iteration {iteration}, attempt {j}: some detailed reason",
                    iter=iteration,
                    now=f"2026-01-{iteration:02d}T00:00:00Z",
                ).consume()

            # Add constraints for this iteration
            neo4j_session.run(
                "CREATE (c:Constraint {"
                "  constraint_id: $cid, content: $content,"
                "  engagement_id: $eid, discovered_iteration: $iter"
                "})",
                cid=str(uuid.uuid4()),
                content=f"Constraint from iteration {iteration}: buffer size limited",
                eid=eid, iter=iteration,
            ).consume()

            # Generate context pack and measure tokens
            pack = generate_context_pack(eid, neo4j_driver, neo4j_config["database"])
            tokens = _count_tokens(pack)
            token_counts.append(tokens)

        # All context packs should be under 4000 tokens
        for i, tc in enumerate(token_counts):
            assert tc < 4000, f"Iteration {i+1}: context pack is {tc} tokens (exceeds 4000)"

        # Token counts should be roughly stable (not growing unboundedly)
        # Allow some growth but the last should not be dramatically larger than the first
        assert token_counts[-1] < token_counts[0] * 5, \
            f"Token growth too large: {token_counts[0]} → {token_counts[-1]}"

    finally:
        neo4j_session.run(
            "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
            eid=eid,
        ).consume()
