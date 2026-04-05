"""Tests for Stage 3: KG MCP server write tools.

10 tests covering happy paths, validation rejections, idempotency,
relationship structures, and auto-stamped metadata.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _mock_ctx(kg_ctx):
    """Build a mock MCP Context wrapping a KgContext."""
    mock = MagicMock()
    mock.request_context.lifespan_context = kg_ctx
    return mock


# ── Test 1: Observation creates full chain ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_observation_creates_chain(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_observation

    result = await kg_record_observation(
        type="behavior",
        summary="Driver writes to user-controlled pointer",
        artifact_uri="file:///exploit_log.txt",
        evidence_locator="lines 45-52",
        evidence_excerpt="memcpy(dest, src, user_len)",
        confidence="high",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "observation_id" in data
    assert "evidence_id" in data
    assert "artifact_id" in data

    # Verify chain in graph
    records = neo4j_session.run(
        "MATCH (o:Observation {observation_id: $oid})"
        "-[:SUPPORTED_BY]->(e:Evidence)"
        "-[:FROM_ARTIFACT]->(a:Artifact) "
        "RETURN o, e, a",
        oid=data["observation_id"],
    ).data()
    assert len(records) == 1
    obs = records[0]["o"]
    assert obs["engagement_id"] == kg_write_context.engagement_id
    assert obs["iteration"] == 1
    assert obs["created_at"] is not None
    assert obs["type"] == "behavior"
    assert obs["status"] == "active"


# ── Test 2: Observation invalid type ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_observation_invalid_type(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_observation

    result = await kg_record_observation(
        type="bogus_type",
        summary="should not be created",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "error" in data
    assert "Invalid type" in data["error"]

    # Verify nothing was created
    records = neo4j_session.run(
        "MATCH (o:Observation {summary: 'should not be created', engagement_id: $eid}) "
        "RETURN count(o) AS c",
        eid=kg_write_context.engagement_id,
    ).data()
    assert records[0]["c"] == 0


# ── Test 3: Attempt idempotent approach ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_attempt_idempotent_approach(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_attempt

    # First attempt
    r1 = await kg_record_attempt(
        approach_name="TokenSwap",
        approach_intent="Swap process tokens for privilege escalation",
        outcome="failure",
        failure_reason="Token offset wrong",
        ctx=_mock_ctx(kg_write_context),
    )
    d1 = json.loads(r1)
    assert "attempt_id" in d1

    # Second attempt with same approach name
    r2 = await kg_record_attempt(
        approach_name="TokenSwap",
        outcome="partial",
        failure_reason="Crash after swap",
        verdict="retry_with_changes",
        ctx=_mock_ctx(kg_write_context),
    )
    d2 = json.loads(r2)
    assert "attempt_id" in d2
    assert d1["attempt_id"] != d2["attempt_id"]

    # Verify: one Approach, two Attempts
    eid = kg_write_context.engagement_id
    approach_count = neo4j_session.run(
        "MATCH (ap:Approach {name: 'TokenSwap', engagement_id: $eid}) RETURN count(ap) AS c",
        eid=eid,
    ).data()[0]["c"]
    assert approach_count == 1

    attempt_count = neo4j_session.run(
        "MATCH (att:Attempt)-[:INSTANCE_OF]->(ap:Approach {name: 'TokenSwap', engagement_id: $eid}) "
        "RETURN count(att) AS c",
        eid=eid,
    ).data()[0]["c"]
    assert attempt_count == 2


# ── Test 4: Constraint empty observation_ids ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_constraint_empty_observation_ids(kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_constraint

    result = await kg_record_constraint(
        content="some constraint",
        observation_ids="[]",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "error" in data
    assert "observation_ids" in data["error"]


# ── Test 5: Constraint with observations ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_constraint_with_observations(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import (
        kg_record_observation,
        kg_record_constraint,
    )

    # Create two observations
    r1 = json.loads(await kg_record_observation(
        type="value", summary="max size is 0x1000",
        ctx=_mock_ctx(kg_write_context),
    ))
    r2 = json.loads(await kg_record_observation(
        type="value", summary="confirmed size cap via testing",
        ctx=_mock_ctx(kg_write_context),
    ))

    # Create constraint linking both
    result = await kg_record_constraint(
        content="Write size limited to 0x1000 bytes",
        verification_method="tested with sizes > 0x1000",
        observation_ids=json.dumps([r1["observation_id"], r2["observation_id"]]),
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "constraint_id" in data
    assert data["linked_observations"] == 2

    # Verify relationships
    records = neo4j_session.run(
        "MATCH (c:Constraint {constraint_id: $cid})-[:DERIVED_FROM]->(o:Observation) "
        "RETURN count(o) AS c",
        cid=data["constraint_id"],
    ).data()
    assert records[0]["c"] == 2


# ── Test 6: Assumption create and update ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_update_assumption_create_and_update(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_update_assumption

    # Create
    r1 = json.loads(await kg_update_assumption(
        content="Heap spray needed for reliable exploitation",
        status="active",
        ctx=_mock_ctx(kg_write_context),
    ))
    assert r1["action"] == "created"
    aid = r1["assumption_id"]

    # Update
    r2 = json.loads(await kg_update_assumption(
        assumption_id=aid,
        content="Heap spray NOT needed — direct overwrite works",
        status="invalidated",
        resolved_basis="Direct overwrite confirmed in iteration 2",
        ctx=_mock_ctx(kg_write_context),
    ))
    assert r2["action"] == "updated"
    assert r2["assumption_id"] == aid

    # Verify updated properties
    records = neo4j_session.run(
        "MATCH (a:Assumption {assumption_id: $aid}) RETURN a",
        aid=aid,
    ).data()
    assert len(records) == 1
    a = records[0]["a"]
    assert a["status"] == "invalidated"
    assert "NOT needed" in a["content"]


# ── Test 7: Protection bypass invalid status ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_update_protection_bypass_invalid_status(kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_update_protection_bypass

    result = await kg_update_protection_bypass(
        protection_name="SMEP",
        bypass_status="bogus_status",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "error" in data
    assert "Invalid bypass_status" in data["error"]


# ── Test 8: Build creates artifacts and relationships ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_build_creates_artifacts(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_build

    result = await kg_record_build(
        source_uri=f"file:///exploit_{kg_write_context.engagement_id}.c",
        source_hash="abc123sourcehash",
        success=True,
        binary_uri=f"file:///exploit_{kg_write_context.engagement_id}.exe",
        binary_hash="def456binaryhash",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "build_id" in data
    assert "source_artifact_id" in data
    assert "binary_artifact_id" in data

    # Verify relationships
    records = neo4j_session.run(
        "MATCH (br:BuildRun {build_id: $bid})-[:COMPILED]->(src:Artifact),"
        "      (br)-[:PRODUCED]->(bin:Artifact) "
        "RETURN src.kind AS src_kind, bin.kind AS bin_kind",
        bid=data["build_id"],
    ).data()
    assert len(records) == 1
    assert records[0]["src_kind"] == "source"
    assert records[0]["bin_kind"] == "binary"


# ── Test 9: Verification creates run with relationships ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_record_verification_creates_run(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_verification

    # Pre-create a binary artifact with sha256
    binary_hash = f"testhash_{uuid.uuid4().hex[:8]}"
    neo4j_session.run(
        "CREATE (a:Artifact {artifact_id: $aid, sha256: $hash, kind: 'binary',"
        "  uri: $uri, engagement_id: $eid})",
        aid=str(uuid.uuid4()),
        hash=binary_hash,
        uri=f"file:///test_binary_{binary_hash}.exe",
        eid=kg_write_context.engagement_id,
    ).consume()

    result = await kg_record_verification(
        binary_hash=binary_hash,
        success=False,
        failure_signature="BSOD 0x50 PAGE_FAULT_IN_NONPAGED_AREA",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    assert "verification_id" in data
    assert data["success"] is False

    # Verify TESTED relationship
    records = neo4j_session.run(
        "MATCH (vr:VerificationRun {verification_id: $vid})-[:TESTED]->(a:Artifact) "
        "RETURN a.sha256 AS hash",
        vid=data["verification_id"],
    ).data()
    assert len(records) == 1
    assert records[0]["hash"] == binary_hash

    # Verify RAN_IN relationship to Environment
    env_records = neo4j_session.run(
        "MATCH (vr:VerificationRun {verification_id: $vid})-[:RAN_IN]->(e:Environment) "
        "RETURN e.environment_id AS env_id",
        vid=data["verification_id"],
    ).data()
    assert len(env_records) == 1
    assert env_records[0]["env_id"] == kg_write_context.environment_id

    # Cleanup verification and environment nodes (not covered by engagement_id)
    neo4j_session.run(
        "MATCH (vr:VerificationRun {verification_id: $vid}) DETACH DELETE vr",
        vid=data["verification_id"],
    ).consume()
    neo4j_session.run(
        "MATCH (e:Environment {environment_id: $eid}) "
        "WHERE NOT EXISTS { MATCH (e)<-[]-() } DELETE e",
        eid=kg_write_context.environment_id,
    ).consume()


# ── Test 10: All tools auto-stamp metadata ──


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_all_tools_auto_stamp_metadata(neo4j_session, kg_write_context):
    from windows_exploit_dev.mcp.kg.tools.write_tools import kg_record_observation

    result = await kg_record_observation(
        type="value",
        summary="metadata stamp test",
        ctx=_mock_ctx(kg_write_context),
    )
    data = json.loads(result)
    oid = data["observation_id"]

    records = neo4j_session.run(
        "MATCH (o:Observation {observation_id: $oid}) RETURN o",
        oid=oid,
    ).data()
    assert len(records) == 1
    o = records[0]["o"]

    assert o["engagement_id"] == kg_write_context.engagement_id
    assert o["iteration"] == 1
    assert o["created_at"] is not None
    assert o["created_by"] == "agent"
    assert o["model_version"] == "test-model-v1"
