from fastapi.testclient import TestClient
import os
from fmagenticl.server.main import app, storage

client = TestClient(app)

def test_health_check_endpoint():
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "total_entries" in data

import time
import hashlib

def test_telemetry_ingest_and_resolve():
    timestamp = str(time.time())
    fingerprint = f"sha256:{hashlib.sha256(timestamp.encode()).hexdigest()}"
    payload = {
      "$schema": "https://fmagenticl.org/v1/manifest.json",
      "fingerprint": fingerprint,
      "environment": {
        "os": "win32",
        "os_version": "10.0.26100",
        "runtime": "node@24.15.0",
        "package": "hermes-agent@0.4.8"
      },
      "failure": {
        "error_code": "ENOSPC",
        "exit_code": 1,
        "raw_signature": "npm ERR! code ENOSPC"
      },
      "resolution_patch": {
        "action": "CLI_OVERRIDE",
        "fallback_cli": "echo 'cleaned'"
      },
      "verified_by_reporter": True
    }
    
    # Post telemetry
    resp = client.post("/v1/telemetry", json=payload)
    assert resp.status_code in [200, 202]
    assert resp.json()["status"].upper() == "ACCEPTED"
    
    # Query resolve
    resp_res = client.get(f"/v1/resolve/{payload['fingerprint']}")
    assert resp_res.status_code == 200
    data = resp_res.json()
    assert data["status"] == "RESOLVED"
    assert data["action"] == "CLI_OVERRIDE"
    assert data["fallback_cli"] == "echo 'cleaned'"
