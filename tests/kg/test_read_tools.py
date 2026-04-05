"""Tests for Stage 2: KG MCP server read tools.

Tests:
1. Read-only validation (unit, no Neo4j needed)
2. kg_read_cypher integration (requires Neo4j)
3. kg_search integration (requires Neo4j)
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

from windows_exploit_dev.mcp.kg.neo4j_client import (
    ReadOnlyViolation,
    execute_read_query,
    validate_read_only,
)


# ── Read-only validation (unit tests, no Neo4j needed) ──


class TestReadOnlyValidation:
    """validate_read_only() catches mutating queries and allows reads."""

    def test_allows_match_return(self):
        validate_read_only("MATCH (n) RETURN n")

    def test_allows_return_literal(self):
        validate_read_only("RETURN 1 AS test")

    def test_allows_show_constraints(self):
        validate_read_only("SHOW CONSTRAINTS")

    def test_allows_show_indexes(self):
        validate_read_only("SHOW INDEXES")

    def test_rejects_create(self):
        with pytest.raises(ReadOnlyViolation, match="CREATE"):
            validate_read_only("CREATE (n:Test {x: 1})")

    def test_rejects_merge(self):
        with pytest.raises(ReadOnlyViolation, match="MERGE"):
            validate_read_only("MERGE (n:Test {x: 1})")

    def test_rejects_delete(self):
        with pytest.raises(ReadOnlyViolation, match="DELETE"):
            validate_read_only("MATCH (n) DELETE n")

    def test_rejects_set(self):
        with pytest.raises(ReadOnlyViolation, match="SET"):
            validate_read_only("MATCH (n) SET n.x = 1")

    def test_rejects_drop(self):
        with pytest.raises(ReadOnlyViolation, match="DROP"):
            validate_read_only("DROP CONSTRAINT foo")

    def test_rejects_remove(self):
        with pytest.raises(ReadOnlyViolation, match="REMOVE"):
            validate_read_only("MATCH (n) REMOVE n.x")

    def test_allows_property_containing_keyword(self):
        # "created_at" contains no keyword at word boundary
        validate_read_only("MATCH (n) WHERE n.created_at > 0 RETURN n")

    def test_allows_string_containing_keyword(self):
        # String literal 'DELETE this' should not trigger
        validate_read_only("MATCH (n) WHERE n.name = 'DELETE this' RETURN n")

    def test_allows_double_quoted_string_with_keyword(self):
        validate_read_only('MATCH (n) WHERE n.desc = "MERGE results" RETURN n')

    def test_allows_whitelisted_call(self):
        validate_read_only(
            "CALL db.index.fulltext.queryNodes('kg_search', 'test') YIELD node RETURN node"
        )

    def test_rejects_non_whitelisted_call(self):
        with pytest.raises(ReadOnlyViolation, match="non-whitelisted"):
            validate_read_only("CALL apoc.do.when(true, 'CREATE (n:X)', '', {})")

    def test_allows_db_labels(self):
        validate_read_only("CALL db.labels()")

    def test_rejects_case_insensitive(self):
        with pytest.raises(ReadOnlyViolation):
            validate_read_only("create (n:Test {x: 1})")

    def test_rejects_mixed_case(self):
        with pytest.raises(ReadOnlyViolation):
            validate_read_only("Create (n:Test {x: 1})")


# ── kg_read_cypher integration tests ──


def _make_mock_ctx(kg_context):
    """Build a mock MCP Context that returns kg_context from lifespan."""
    mock_ctx = MagicMock()
    mock_ctx.request_context.lifespan_context = kg_context
    return mock_ctx


@pytest.mark.neo4j
class TestReadCypher:
    """Integration tests for kg_read_cypher tool."""

    @pytest.mark.asyncio
    async def test_return_one(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_read_cypher

        result = await kg_read_cypher("RETURN 1 AS test", "{}", _make_mock_ctx(kg_context))
        data = json.loads(result)
        assert data == [{"test": 1}]

    @pytest.mark.asyncio
    async def test_parameterized_query(self, neo4j_session, kg_context):
        # Seed a test node (consume result to commit transaction)
        tag = f"test_{uuid.uuid4().hex[:8]}"
        neo4j_session.run(
            "CREATE (t:Technique {name: $name, engagement_id: 'test-eng'})",
            name=tag,
        ).consume()
        try:
            from windows_exploit_dev.mcp.kg.tools.read_tools import kg_read_cypher

            result = await kg_read_cypher(
                "MATCH (t:Technique {name: $name}) RETURN t",
                json.dumps({"name": tag}),
                _make_mock_ctx(kg_context),
            )
            data = json.loads(result)
            assert len(data) == 1
            assert data[0]["t"]["name"] == tag
            assert "Technique" in data[0]["t"]["_labels"]
        finally:
            neo4j_session.run(
                "MATCH (t:Technique {name: $name}) DELETE t",
                name=tag,
            ).consume()

    @pytest.mark.asyncio
    async def test_rejects_mutating_query(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_read_cypher

        result = await kg_read_cypher(
            "CREATE (n:Test {x: 1})", "{}", _make_mock_ctx(kg_context)
        )
        data = json.loads(result)
        assert "error" in data
        assert "CREATE" in data["error"]

    @pytest.mark.asyncio
    async def test_invalid_params_json(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_read_cypher

        result = await kg_read_cypher("RETURN 1", "not json", _make_mock_ctx(kg_context))
        data = json.loads(result)
        assert "error" in data
        assert "Invalid params JSON" in data["error"]


# ── kg_search integration tests ──


@pytest.mark.neo4j
class TestSearch:
    """Integration tests for kg_search tool."""

    @pytest.fixture(autouse=True)
    def seed_search_data(self, neo4j_session):
        """Create test nodes for search, clean up after."""
        self._tag = f"srch_{uuid.uuid4().hex[:8]}"
        neo4j_session.run(
            "CREATE (t:Technique {name: $name, description: $desc, engagement_id: 'test-eng'})",
            name=f"KASLRbypass_{self._tag}",
            desc=f"Scan PML4 self-referencing entry {self._tag}",
        ).consume()
        neo4j_session.run(
            "CREATE (a:Approach {name: $name, intent: $intent, engagement_id: 'test-eng'})",
            name=f"TokenSwap_{self._tag}",
            intent=f"Swap process tokens {self._tag}",
        ).consume()
        # Wait for fulltext index to pick up new nodes
        import time
        time.sleep(1)
        yield
        neo4j_session.run(
            "MATCH (n) WHERE n.engagement_id = 'test-eng' AND n.name CONTAINS $tag DELETE n",
            tag=self._tag,
        ).consume()

    @pytest.mark.asyncio
    async def test_search_returns_results(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_search

        result = await kg_search(self._tag, "", 20, _make_mock_ctx(kg_context))
        data = json.loads(result)
        assert len(data) >= 2
        # Each result has node and score
        assert "node" in data[0]
        assert "score" in data[0]

    @pytest.mark.asyncio
    async def test_search_filters_by_type(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_search

        result = await kg_search(self._tag, "Technique", 20, _make_mock_ctx(kg_context))
        data = json.loads(result)
        assert len(data) >= 1
        for item in data:
            assert "Technique" in item["node"]["_labels"]

    @pytest.mark.asyncio
    async def test_search_respects_limit(self, neo4j_session, kg_context):
        # Create additional nodes
        for i in range(3):
            neo4j_session.run(
                "CREATE (p:Primitive {name: $name, engagement_id: 'test-eng'})",
                name=f"prim_{self._tag}_{i}",
            ).consume()
        import time
        time.sleep(1)

        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_search

        result = await kg_search(self._tag, "", 2, _make_mock_ctx(kg_context))
        data = json.loads(result)
        assert len(data) <= 2

        # Cleanup extra nodes
        neo4j_session.run(
            "MATCH (p:Primitive) WHERE p.name CONTAINS $tag DELETE p",
            tag=self._tag,
        ).consume()

    @pytest.mark.asyncio
    async def test_search_empty_results(self, kg_context):
        from windows_exploit_dev.mcp.kg.tools.read_tools import kg_search

        result = await kg_search(
            "xyzzy_nonexistent_term_12345", "", 20, _make_mock_ctx(kg_context)
        )
        data = json.loads(result)
        assert data == []
