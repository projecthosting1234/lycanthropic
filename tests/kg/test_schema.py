"""Schema deployment and validation tests for the knowledge graph.

Tests:
1. Smoke — connect, RETURN 1, CRUD on test node
2. Schema init — run init.cypher, verify all indexes and constraints
3. Idempotency — run init.cypher twice, no errors or duplicates
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from windows_exploit_dev.kg.schema.apply import apply_schema

EXPECTED_CONSTRAINTS = {
    "approach_unique",
    "technique_unique",
    "primitive_unique",
    "protection_unique",
    "driver_unique",
    "artifact_uid",
    "evidence_uid",
    "observation_uid",
    "attempt_uid",
    "constraint_uid",
    "assumption_uid",
    "engagement_uid",
    "iteration_uid",
    "environment_uid",
    "build_uid",
    "verification_uid",
    "vulnerability_uid",
}

EXPECTED_INDEXES = {
    "attempt_iteration",
    "attempt_outcome",
    "observation_status",
    "assumption_status",
    "artifact_engagement",
    "kg_search",
}


@pytest.mark.neo4j
class TestSmoke:
    """Basic connectivity and CRUD smoke tests."""

    def test_return_one(self, neo4j_session):
        result = neo4j_session.run("RETURN 1 AS n")
        record = result.single()
        assert record["n"] == 1

    def test_create_query_delete_node(self, neo4j_session):
        # Create
        neo4j_session.run(
            "CREATE (t:_Test {name: $name})",
            name="smoke_test_node",
        )
        # Query
        result = neo4j_session.run(
            "MATCH (t:_Test {name: $name}) RETURN t.name AS name",
            name="smoke_test_node",
        )
        record = result.single()
        assert record is not None
        assert record["name"] == "smoke_test_node"
        # Delete
        neo4j_session.run(
            "MATCH (t:_Test {name: $name}) DELETE t",
            name="smoke_test_node",
        )
        # Verify deletion
        result = neo4j_session.run(
            "MATCH (t:_Test {name: $name}) RETURN count(t) AS c",
            name="smoke_test_node",
        )
        assert result.single()["c"] == 0


@pytest.mark.neo4j
class TestSchemaDeployment:
    """Schema init and validation."""

    def test_apply_schema(self, neo4j_config):
        statements = apply_schema(
            uri=neo4j_config["uri"],
            username=neo4j_config["username"],
            password=neo4j_config["password"],
            database=neo4j_config["database"],
        )
        # 4 composite + 11 UUID constraints + 5 indexes + 1 fulltext = 21
        assert len(statements) == 23

    def test_all_constraints_exist(self, neo4j_session):
        result = neo4j_session.run("SHOW CONSTRAINTS")
        found = {record["name"] for record in result}
        missing = EXPECTED_CONSTRAINTS - found
        assert not missing, f"Missing constraints: {missing}"

    def test_all_indexes_exist(self, neo4j_session):
        result = neo4j_session.run("SHOW INDEXES")
        found = {record["name"] for record in result}
        missing = EXPECTED_INDEXES - found
        assert not missing, f"Missing indexes: {missing}"

    def test_fulltext_index_type(self, neo4j_session):
        result = neo4j_session.run(
            "SHOW INDEXES WHERE name = 'kg_search'"
        )
        record = result.single()
        assert record is not None
        assert record["type"] == "FULLTEXT"


@pytest.mark.neo4j
class TestIdempotency:
    """Running init.cypher multiple times is safe."""

    def test_second_apply_no_errors(self, neo4j_config):
        # First apply (may already be applied)
        apply_schema(
            uri=neo4j_config["uri"],
            username=neo4j_config["username"],
            password=neo4j_config["password"],
            database=neo4j_config["database"],
        )
        # Second apply — must not raise
        statements = apply_schema(
            uri=neo4j_config["uri"],
            username=neo4j_config["username"],
            password=neo4j_config["password"],
            database=neo4j_config["database"],
        )
        assert len(statements) == 23

    def test_constraint_count_unchanged(self, neo4j_session):
        result = neo4j_session.run("SHOW CONSTRAINTS")
        all_names = [record["name"] for record in result]
        # No duplicates
        assert len(all_names) == len(set(all_names))
