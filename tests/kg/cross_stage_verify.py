"""Cross-stage integration verification: exercises all 7 stages end-to-end."""

import json
import uuid
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import yaml

from windows_exploit_dev.mcp.kg.neo4j_client import (
    create_driver, execute_write_query, execute_read_query,
    ReadOnlyViolation, validate_read_only,
)

driver = create_driver("bolt://127.0.0.1:7687", "neo4j", "lpefinder")
driver.verify_connectivity()
eid = f"cross-{uuid.uuid4().hex[:8]}"
env_id = f"env-{uuid.uuid4().hex[:8]}"
os.environ["KG_ENGAGEMENT_ID"] = eid
os.environ["KG_ENVIRONMENT_ID"] = env_id
errors = []

def check(name, condition, detail=""):
    if condition:
        print(f"  [OK] {name}")
    else:
        print(f"  [FAIL] {name}: {detail}")
        errors.append(name)

print("=" * 60)
print("CROSS-STAGE INTEGRATION VERIFICATION")
print("=" * 60)
print(f"Engagement: {eid}")

# ── STAGE 1: Schema ──
print("\n-- Stage 1: Schema --")
constraints = execute_read_query(driver, "neo4j", "SHOW CONSTRAINTS")
check("Constraints >= 17", len(constraints) >= 17, f"got {len(constraints)}")

# ── STAGE 2: Read-only validation ──
print("\n-- Stage 2: Read tools --")
validate_read_only("MATCH (n) RETURN n")
try:
    validate_read_only("CREATE (n:X)")
    check("Rejects CREATE", False, "did not raise")
except ReadOnlyViolation:
    check("Rejects CREATE", True)

# ── STAGE 3: Write tools ──
print("\n-- Stage 3: Write tools --")
from unittest.mock import MagicMock
from windows_exploit_dev.mcp.kg.server import KgContext
import asyncio
from windows_exploit_dev.mcp.kg.tools.write_tools import (
    kg_record_observation, kg_record_attempt, kg_record_constraint,
    kg_update_assumption, kg_update_protection_bypass, kg_update_primitive,
    kg_record_build, kg_record_verification,
)

kctx = KgContext(driver=driver, database="neo4j", engagement_id=eid,
                 iteration=1, environment_id=env_id, model_version="test")
mock = MagicMock()
mock.request_context.lifespan_context = kctx

obs_r = json.loads(asyncio.run(kg_record_observation(
    type="behavior", summary="PhysMem map works on ECAM",
    artifact_uri="file:///log.txt", evidence_locator="line 42",
    evidence_excerpt="MmMapIoSpace OK", confidence="high", ctx=mock)))
check("kg_record_observation", "observation_id" in obs_r)

att_r = json.loads(asyncio.run(kg_record_attempt(
    approach_name="TokenSwap", outcome="failure",
    technique="PML4_scan", primitive="physical_memory_map",
    failure_reason="BSOD on cached RAM", verdict="dead_end", ctx=mock)))
check("kg_record_attempt", "attempt_id" in att_r)

con_r = json.loads(asyncio.run(kg_record_constraint(
    content="Cannot map cached RAM", verification_method="BSOD test",
    observation_ids=json.dumps([obs_r["observation_id"]]),
    affects=json.dumps(["physical_memory_map"]), ctx=mock)))
check("kg_record_constraint", con_r.get("linked_observations") == 1)

asn_r = json.loads(asyncio.run(kg_update_assumption(
    content="ECAM has useful bytes", status="active", ctx=mock)))
check("kg_update_assumption", asn_r.get("action") == "created")

prot_r = json.loads(asyncio.run(kg_update_protection_bypass(
    protection_name="KASLR", bypass_status="in_progress",
    bypass_method="ECAM scan", ctx=mock)))
check("kg_update_protection_bypass", prot_r.get("bypass_status") == "in_progress")

prim_r = json.loads(asyncio.run(kg_update_primitive(
    primitive_name="physical_memory_map", verified=True,
    verification_method="Confirmed on ECAM", ctx=mock)))
check("kg_update_primitive", prim_r.get("verified") == True)

build_r = json.loads(asyncio.run(kg_record_build(
    source_uri=f"file:///exploit_{eid}.c", source_hash="abc",
    success=True, binary_uri=f"file:///exploit_{eid}.exe",
    binary_hash="def456", ctx=mock)))
check("kg_record_build", "build_id" in build_r and "binary_artifact_id" in build_r)

ver_r = json.loads(asyncio.run(kg_record_verification(
    binary_hash="def456", success=False,
    failure_signature="KASLR returns 0x0", ctx=mock)))
check("kg_record_verification", "verification_id" in ver_r)

# Verify enum validation rejects bad values
bad_r = json.loads(asyncio.run(kg_record_observation(
    type="INVALID", summary="x", ctx=mock)))
check("Enum validation rejects bad type", "error" in bad_r)

# ── STAGE 4: Context Pack reflects Stage 3 writes ──
print("\n-- Stage 4: Context Pack --")
from windows_exploit_dev.pipeline.context_pack import generate_context_pack, _count_tokens

pack = generate_context_pack(eid, driver, "neo4j")
tokens = _count_tokens(pack)
cp = yaml.safe_load(pack)["context_pack"]

check("Token count < 4000", tokens < 4000, f"got {tokens}")
check("Has verified primitive", any(p.get("verified") for p in cp["primitives"]))
kaslr = [p for p in cp["protections"] if p["name"] == "KASLR"]
check("KASLR is in_progress", kaslr and kaslr[0]["bypass_status"] == "in_progress")
check("Has failed attempts", len(cp["failed_attempts"]) >= 1)
check("Has constraints", len(cp["constraints"]) >= 1)
check("Has assumptions", len(cp["assumptions"]) >= 1)
check("Has recent builds", len(cp.get("recent_builds", [])) >= 1)

# ── STAGE 5: Prompt integration ──
print("\n-- Stage 5: Prompt integration --")
from windows_exploit_dev.pipeline.agent_prompt import build_analysis_prompt

prompt = build_analysis_prompt(
    None, "test_svc", "", iteration=2,
    handoff_content=None, initial_info="Init info.", context_pack_yaml=pack)

check("Prompt has context pack", "Knowledge Graph Context Pack" in prompt)
check("Prompt has NO handoff", "Previous Iteration Handoff" not in prompt)
check("Prompt has NO EXPLOIT_STATE", "Cumulative Exploit State" not in prompt)
check("Prompt has initial info", "Initial Information" in prompt)
check("Prompt has KG tool docs", "kg_record_observation" in prompt)
check("Prompt has turn budget", "TURN BUDGET" in prompt)

# MCP config writer
from windows_exploit_dev.pipeline.mcp_config_writer import write_mcp_config, restore_mcp_config
p = write_mcp_config(engagement_id=eid, iteration_number=2, environment_id=env_id)
cfg = json.loads(p.read_text())
check("MCP config has kg server", "kg" in cfg["mcpServers"])
check("MCP config has engagement env", cfg["mcpServers"]["kg"].get("env", {}).get("KG_ENGAGEMENT_ID") == eid)
restore_mcp_config()

# Iter 1 still uses handoff
prompt1 = build_analysis_prompt(None, "svc", "", iteration=1, handoff_content="Init")
check("Iter 1 uses handoff", "Initial Information" in prompt1)
check("Iter 1 no context pack", "Knowledge Graph Context Pack" not in prompt1)

# ── STAGE 6: Projections + Reconciliation ──
print("\n-- Stage 6: Projections + Reconciliation --")
from windows_exploit_dev.kg.projections.exploit_state_report import generate_exploit_state_report
from windows_exploit_dev.kg.projections.handoff_report import generate_handoff_report
from windows_exploit_dev.kg.reconciliation import reconcile_handoff

state_md = generate_exploit_state_report(eid, driver, "neo4j")
check("EXPLOIT_STATE has dead ends", "**TokenSwap**" in state_md)
check("EXPLOIT_STATE format correct", "Dead Ends" in state_md)

handoff_md = generate_handoff_report(eid, 1, driver, "neo4j")
check("Handoff has iteration header", "Iteration 1 Handoff" in handoff_md)
check("Handoff has dead-end markers", "DEAD_ENDS_START" in handoff_md)

# Reconcile new handoff and verify it appears in context pack
recon = reconcile_handoff(
    "## DEAD ENDS\n<!-- DEAD_ENDS_START -->\n"
    "- **HeapSpray**: OOM. Evidence: alloc failed\n"
    "<!-- DEAD_ENDS_END -->\n## Verification\n**FAILED**: BSOD\n",
    eid, 2, driver, "neo4j")
check("Reconciliation records dead ends", recon["dead_ends"] == 1)
check("Reconciliation records verification", recon["verifications"] == 1)

pack3 = generate_context_pack(eid, driver, "neo4j")
cp3 = yaml.safe_load(pack3)["context_pack"]
heap_found = any("HeapSpray" in a.get("approach", "") for a in cp3["failed_attempts"])
check("Reconciled data in context pack", heap_found)

# ── STAGE 7: Validation + Dashboard ──
print("\n-- Stage 7: Validation + Dashboard --")
from windows_exploit_dev.kg.validate_graph import validate_graph

# Clean orphan evidence first (from other test runs)
execute_write_query(driver, "neo4j",
    "MATCH (e:Evidence) WHERE NOT EXISTS { MATCH (:Observation)-[:SUPPORTED_BY]->(e) } DELETE e", {})

results = validate_graph(eid, driver, "neo4j")
for r in results:
    status = "OK" if r["status"] == "pass" else f'FAIL({r["count"]})'
    print(f"    {r['check']}: {status}")
all_pass = all(r["status"] == "pass" for r in results)
check("All 7 validation checks pass", all_pass,
      "; ".join(f"{r['check']}:{r['count']}" for r in results if r["status"] == "fail"))

dash = json.loads(Path("windows_exploit_dev/kg/dashboard/lpe_finder_dashboard.json").read_text())
check("Dashboard has 5 pages", len(dash["pages"]) == 5)

# ── PROVENANCE CHAIN ──
print("\n-- Provenance chain --")
chain = execute_read_query(driver, "neo4j",
    "MATCH (c:Constraint {engagement_id: $eid})"
    "-[:DERIVED_FROM]->(o:Observation)"
    "-[:SUPPORTED_BY]->(e:Evidence)"
    "-[:FROM_ARTIFACT]->(a:Artifact) "
    "RETURN c.content AS c, o.summary AS o, e.excerpt AS e, a.uri AS a",
    {"eid": eid})
check("Complete provenance chain exists", len(chain) >= 1, f"chains: {len(chain)}")
if chain:
    print(f"    Constraint: {chain[0]['c'][:40]}")
    print(f"    -> Observation: {chain[0]['o'][:40]}")
    print(f"    -> Evidence: {chain[0]['e'][:40]}")
    print(f"    -> Artifact: {chain[0]['a'][:40]}")

# ── CLEANUP ──
execute_write_query(driver, "neo4j",
    "MATCH (n) WHERE n.engagement_id = $eid DETACH DELETE n", {"eid": eid})
execute_write_query(driver, "neo4j",
    "MATCH (e:Evidence) WHERE NOT EXISTS { MATCH ()-[:SUPPORTED_BY]->(e) } DELETE e", {})
driver.close()
os.environ.pop("KG_ENGAGEMENT_ID", None)
os.environ.pop("KG_ENVIRONMENT_ID", None)

print("\n" + "=" * 60)
if errors:
    print(f"FAILED: {len(errors)} checks failed: {errors}")
    sys.exit(1)
else:
    print("ALL CROSS-STAGE CHECKS PASSED")
print("=" * 60)
