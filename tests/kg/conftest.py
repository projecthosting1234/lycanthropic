"""Fixtures for knowledge graph tests.

These tests require a running Neo4j instance (via docker compose).
Tests are auto-skipped when Neo4j is unreachable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

_DEFAULT_URI = "bolt://127.0.0.1:7687"
_DEFAULT_USER = "neo4j"
_DEFAULT_PASS = "lpefinder"
_DEFAULT_DB = "neo4j"


def _load_neo4j_config() -> dict:
    """Load neo4j config from config.json, falling back to defaults."""
    config_path = Path(_PROJECT_ROOT) / "config.json"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        neo4j_cfg = cfg.get("neo4j", {})
        return {
            "uri": neo4j_cfg.get("uri", _DEFAULT_URI),
            "username": neo4j_cfg.get("username", _DEFAULT_USER),
            "password": neo4j_cfg.get("password", _DEFAULT_PASS),
            "database": neo4j_cfg.get("database", _DEFAULT_DB),
        }
    return {
        "uri": _DEFAULT_URI,
        "username": _DEFAULT_USER,
        "password": _DEFAULT_PASS,
        "database": _DEFAULT_DB,
    }


def pytest_configure(config):
    """Register the neo4j marker."""
    config.addinivalue_line(
        "markers", "neo4j: marks tests requiring a running Neo4j instance"
    )


@pytest.fixture(scope="session")
def neo4j_config() -> dict:
    """Return Neo4j connection config dict."""
    return _load_neo4j_config()


@pytest.fixture(scope="session")
def neo4j_driver(neo4j_config):
    """Create a neo4j Driver scoped to the test session.

    Skips all tests if Neo4j is not reachable.
    """
    import neo4j

    driver = neo4j.GraphDatabase.driver(
        neo4j_config["uri"],
        auth=(neo4j_config["username"], neo4j_config["password"]),
    )
    try:
        driver.verify_connectivity()
    except Exception as exc:
        driver.close()
        pytest.skip(f"Neo4j not reachable: {exc}")

    yield driver
    driver.close()


@pytest.fixture(scope="session")
def neo4j_session(neo4j_driver, neo4j_config):
    """Create a neo4j Session scoped to the test session."""
    with neo4j_driver.session(database=neo4j_config["database"]) as session:
        yield session


@pytest.fixture(scope="session")
def kg_context(neo4j_driver, neo4j_config):
    """Create a KgContext for direct tool testing."""
    from windows_exploit_dev.mcp.kg.server import KgContext
    return KgContext(driver=neo4j_driver, database=neo4j_config["database"])


@pytest.fixture
def kg_write_context(neo4j_driver, neo4j_config, neo4j_session):
    """KgContext with engagement/iteration/environment for write tests.

    Per-test scope — each test gets a unique engagement_id for isolation.
    Cleanup deletes all nodes with that engagement_id after the test.
    """
    import uuid as _uuid
    from windows_exploit_dev.mcp.kg.server import KgContext

    eid = f"test-eng-{_uuid.uuid4().hex[:8]}"
    ctx = KgContext(
        driver=neo4j_driver,
        database=neo4j_config["database"],
        engagement_id=eid,
        iteration=1,
        environment_id=f"test-env-{_uuid.uuid4().hex[:8]}",
        model_version="test-model-v1",
    )
    yield ctx
    # Cleanup all nodes created with this engagement_id
    neo4j_session.run(
        "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n",
        eid=eid,
    ).consume()
