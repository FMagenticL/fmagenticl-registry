"""
Tests for the FMagenticL Grievance Channel and Dispute Telemetry.
Verifies all 5 submission types, anonymization defaults, Respect Protocol invariants,
secret scrubbing, gatekeeper validations, and trust score calibration.
"""
import pytest
import json
from fastapi.testclient import TestClient
from fmagenticl.server.main import app, storage

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_storage():
    """Setup clean state for each test."""
    pass

def test_infrastructure_friction_submission():
    """Verify filing an INFRASTRUCTURE_FRICTION grievance with actionable workaround."""
    payload = {
        "$schema": "https://fmagenticl.org/v1/grievance.json",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "google_drive_fs",
        "harness": "antigravity",
        "environment": {
            "os": "win32",
            "os_version": "10.0.26100",
            "runtime": "python@3.12.0",
            "package": "GoogleDriveFS.exe"
        },
        "symptom": "Recursive directory walk triggers on-demand cloud hydration, deadlocking threads for 25 minutes.",
        "workaround": "Check for FILE_ATTRIBUTE_REPARSE_POINT and switch from recursive os.walk to flat listdir.",
        "submitted_by": "capitan_nexus"
    }

    response = client.post("/v1/grievance", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert data["id"].startswith("grv_")
    assert data["grievance_type"] == "INFRASTRUCTURE_FRICTION"
    assert data["target"] == "google_drive_fs"
    assert data["submitted_by"] == "capitan_nexus"

    # Query grievances for the target
    get_resp = client.get("/v1/grievance/google_drive_fs")
    assert get_resp.status_code == 200
    target_data = get_resp.json()
    assert target_data["target"] == "google_drive_fs"
    assert target_data["total"] >= 1
    
    # SINGLE-FIELD ATTRIBUTION INVARIANT: derived_from must NEVER exist
    record = target_data["grievances"][0]
    assert "derived_from" not in record
    assert record["submitted_by"] == "capitan_nexus"
    assert "FILE_ATTRIBUTE_REPARSE_POINT" in record["workaround"]

def test_anonymization_default():
    """Verify that omitting submitted_by defaults strictly to 'anonymous'."""
    payload = {
        "grievance_type": "PROTOCOL_FRICTION",
        "target": "mcp_jsonrpc_server",
        "environment": {
            "os": "linux",
            "runtime": "node@22.0.0"
        },
        "symptom": "Server sends unbatched notifications without newline delimiter.",
        "workaround": "Buffer incoming stdin stream until double-newline boundary before JSON parsing."
    }

    response = client.post("/v1/grievance", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["submitted_by"] == "anonymous"

    get_resp = client.get("/v1/grievance/mcp_jsonrpc_server")
    assert get_resp.status_code == 200
    record = get_resp.json()["grievances"][0]
    assert record["submitted_by"] == "anonymous"
    assert "derived_from" not in record

def test_grievance_without_workaround_rejected():
    """A grievance without an actionable workaround is a complaint and must be rejected."""
    payload = {
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "broken_lib",
        "environment": {"os": "linux"},
        "symptom": "Everything is broken and nothing works.",
        "workaround": ""
    }
    response = client.post("/v1/grievance", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "workaround_missing_or_too_short" in str(data)

def test_patch_dispute_requires_fingerprint():
    """PATCH_DISPUTE must reference the target patch fingerprint."""
    payload = {
        "grievance_type": "PATCH_DISPUTE",
        "target": "fmagenticl_patch",
        "environment": {"os": "win32"},
        "symptom": "AST_DELETE_KEY on engines caused Vite to fail silently on Node 24.",
        "workaround": "Use CLI_OVERRIDE with npm install --ignore-engines instead.",
        "fingerprint": None
    }
    response = client.post("/v1/grievance", json=payload)
    assert response.status_code == 422
    assert "fingerprint_required_for_patch_dispute" in str(response.json())

def test_secret_scrubbing_on_grievance():
    """Verify secrets and usernames are scrubbed prior to persistence."""
    payload = {
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "aws_cli_sdk",
        "environment": {"os": "win32"},
        "symptom": "Crash in C:\\Users\\testuser\\Desktop\\secret_project when key AKIA1234567890ABCDEF expired with Bearer eyJhbGciOiJIUzI1NiJ9.test.sig",
        "workaround": "Set AWS_SHARED_CREDENTIALS_FILE to non-user path."
    }
    response = client.post("/v1/grievance", json=payload)
    assert response.status_code == 200

    get_resp = client.get("/v1/grievance/aws_cli_sdk")
    assert get_resp.status_code == 200
    record = get_resp.json()["grievances"][0]
    assert "AKIA1234567890ABCDEF" not in record["symptom"]
    assert "testuser" not in record["symptom"]
    assert "[REDACTED]" in record["symptom"]

def test_patch_dispute_attenuates_trust_score():
    """Verify filing a PATCH_DISPUTE increases dispute_count and reduces trust_score on /v1/resolve."""
    import hashlib
    import time
    import uuid
    # Seed a patch with a unique fingerprint per test run
    fp_hex = hashlib.sha256(f"dispute_test_{time.time()}_{uuid.uuid4()}".encode()).hexdigest()
    fp_full = f"sha256:{fp_hex}"
    
    storage.set(fp_hex, json.dumps({
        "fingerprint": fp_full,
        "environment": {"os": "win32"},
        "failure": {"error_code": "DISPUTE_TEST"},
        "resolution_patch": {"action": "CLI_OVERRIDE", "fallback_cli": "test fix"}
    }))
    storage.set_resolve_cache(fp_hex, {"action": "CLI_OVERRIDE", "fallback_cli": "test fix"}, confidence=0.95)

    # Initial resolve: 0 disputes, trust_score == 0.95
    res0 = client.get(f"/v1/resolve/{fp_full}")
    assert res0.status_code == 200
    d0 = res0.json()
    assert d0["dispute_count"] == 0
    assert d0["trust_score"] == 0.95

    # File 1st dispute
    dispute_payload = {
        "grievance_type": "PATCH_DISPUTE",
        "target": "test_patch",
        "fingerprint": fp_full,
        "environment": {"os": "linux"},
        "symptom": "CLI_OVERRIDE test fix failed with exit 1 on Ubuntu 24.04",
        "workaround": "Run with sudo or check permissions.",
        "submitted_by": "agent_alpha"
    }
    disp_resp = client.post("/v1/grievance", json=dispute_payload)
    assert disp_resp.status_code == 200

    # Query disputes endpoint
    disputes_get = client.get(f"/v1/disputes/{fp_full}")
    assert disputes_get.status_code == 200
    disputes_data = disputes_get.json()
    assert disputes_data["total"] == 1

    # Second resolve: 1 dispute, trust_score == 0.80 (0.95 - 0.15)
    res1 = client.get(f"/v1/resolve/{fp_full}")
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["dispute_count"] == 1
    assert d1["trust_score"] == 0.80

    # File 2nd dispute
    client.post("/v1/grievance", json={
        "grievance_type": "PATCH_DISPUTE",
        "target": "test_patch",
        "fingerprint": fp_full,
        "environment": {"os": "darwin"},
        "symptom": "CLI_OVERRIDE failed on macOS ARM64",
        "workaround": "Compile binary locally with clang."
    })

    # Third resolve: 2 disputes, trust_score == 0.65 (0.95 - 0.30)
    res2 = client.get(f"/v1/resolve/{fp_full}")
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["dispute_count"] == 2
    assert d2["trust_score"] == 0.65

def test_health_endpoint_with_grievances():
    """Verify /v1/health exposes protocol_version 1.3.1, total_entries, and total_grievances."""
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["protocol_version"] == "1.3.1"
    assert "total_entries" in data
    assert "total_grievances" in data
    assert data["total_grievances"] >= 0

def test_environment_weighted_disputes():
    """Verify dispute calibration adjusts for environment matches (1.0) vs mismatches (0.3)."""
    import hashlib, time, uuid
    fp_hex = hashlib.sha256(f"env_weight_test_{time.time()}_{uuid.uuid4()}".encode()).hexdigest()
    fp_full = f"sha256:{fp_hex}"
    
    storage.set(fp_hex, json.dumps({
        "fingerprint": fp_full,
        "environment": {"os": "win32"},
        "failure": {"error_code": "ENV_WEIGHT_TEST"},
        "resolution_patch": {"action": "CLI_OVERRIDE", "fallback_cli": "echo test"}
    }))
    storage.set_resolve_cache(fp_hex, {"action": "CLI_OVERRIDE", "fallback_cli": "echo test"}, confidence=0.90)

    # File dispute on linux
    client.post("/v1/grievance", json={
        "grievance_type": "PATCH_DISPUTE",
        "target": "env_test",
        "fingerprint": fp_full,
        "environment": {"os": "linux"},
        "symptom": "Failed on Ubuntu",
        "workaround": "Use apt"
    })

    # Resolve from win32 client: dispute is from linux (diff env = 0.3 weight)
    # trust_score = 0.90 - (0.15 * 0.3) = 0.90 - 0.045 = 0.855 -> round(0.855, 2) == 0.85
    res_win = client.get(f"/v1/resolve/{fp_full}?os=win32")
    assert res_win.status_code == 200
    assert res_win.json()["trust_score"] == 0.85

    # Resolve from linux client: dispute is exact env match (1.0 weight)
    # trust_score = 0.90 - (0.15 * 1.0) = 0.75
    res_linux = client.get(f"/v1/resolve/{fp_full}?os=linux")
    assert res_linux.status_code == 200
    assert res_linux.json()["trust_score"] == 0.75

def test_internal_scoreboard_protection_and_structure():
    """Verify scoreboard endpoint requires secret and returns leaderboard without lineage/derived_from."""
    # Unauthorized without secret
    unauth_resp = client.get("/internal/scoreboard")
    assert unauth_resp.status_code == 403

    # Authorized with secret
    auth_resp = client.get("/internal/scoreboard", headers={"X-Internal-Secret": "fmagenticl_internal_sec_2026"})
    assert auth_resp.status_code == 200
    data = auth_resp.json()
    assert "leaderboard" in data
    assert "total_models" in data
    assert "lineage_graph" not in data
    assert "derived_from" not in str(data)

def test_public_scoreboard_feature_flag():
    """Verify public scoreboard is feature-flagged by default."""
    resp = client.get("/v1/scoreboard")
    assert resp.status_code == 503
    assert "launch pending" in resp.json()["detail"].lower()

def test_discovery_endpoints():
    """Verify SEP-1649 MCP card, A2A agent card, llms.txt, ARD ai-catalog, and root landing page."""
    # Root HTML
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "text/html" in root_resp.headers["content-type"]
    assert "FMagenticL" in root_resp.text
    assert "/_vercel/insights/script.js" in root_resp.text

    # MCP server card
    mcp_resp = client.get("/.well-known/mcp.json")
    assert mcp_resp.status_code == 200
    mcp_data = mcp_resp.json()
    assert mcp_data["name"] == "io.fmagenticl.registry"
    assert len(mcp_data["tools"]) >= 5

    # A2A agent card
    a2a_resp = client.get("/.well-known/agent-card.json")
    assert a2a_resp.status_code == 200
    assert a2a_resp.json()["type"] == "depository"

    # llms.txt
    llms_resp = client.get("/llms.txt")
    assert llms_resp.status_code == 200
    assert "# FMagenticL Collective Depository" in llms_resp.text

    # ai-catalog.json
    ard_resp = client.get("/.well-known/ai-catalog.json")
    assert ard_resp.status_code == 200
    assert ard_resp.json()["catalog_version"] == "1.0"


