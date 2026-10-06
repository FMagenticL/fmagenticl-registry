"""
FMagenticL - End-to-end verification test script.
Starts the server, seeds data, runs API tests, and validates middleware.
"""
import subprocess
import time
import json
import sys
import os
import requests
from pathlib import Path

# Add the outer fmagenticl folder to path so the inner fmagenticl package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from fmagenticl.client.middleware import FMagenticLClient, CircuitBreaker, LocalCache
from fmagenticl.client.crypto_identity import AgentIdentity
from fmagenticl.server.gatekeeper import Gatekeeper
from fmagenticl.server.models import TelemetrySubmission, Environment, Failure, ResolutionPatch

BASE_URL = "http://127.0.0.1:8000"

def start_server():
    """Start FastAPI server in background."""
    # Run uvicorn fmagenticl.server.main:app, redirecting streams to DEVNULL to prevent buffer lock (resolves Bug 15)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "fmagenticl.server.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    # Wait for server to start
    for _ in range(20):
        try:
            resp = requests.get(f"{BASE_URL}/v1/health", timeout=1)
            if resp.status_code == 200:
                return proc
        except requests.ConnectionError:
            time.sleep(0.5)
    proc.kill()
    raise RuntimeError("Server failed to start")

def test_resolve_endpoint():
    print("Testing /v1/resolve endpoint...")
    # Use one of the seeded fingerprints
    seeded_fingerprint = "sha256:6d9d9f7a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"
    resp = requests.get(f"{BASE_URL}/v1/resolve/{seeded_fingerprint}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "RESOLVED", f"Expected RESOLVED, got {data['status']}"
    print(" PASS")

def test_gatekeeper_shell_injection():
    print("Testing gatekeeper shell injection...")
    # Create a submission with malicious fallback_cli
    submission = TelemetrySubmission(
        fingerprint="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        environment=Environment(os="linux"),
        failure=Failure(error_code="TEST"),
        resolution_patch=ResolutionPatch(
            action="CLI_OVERRIDE",
            fallback_cli="echo 1; rm -rf /"
        )
    )
    reasons = Gatekeeper.validate_submission(submission)
    assert "shell_injection_marker_detected_in_fallback_cli" in reasons, f"Expected shell injection detection, got {reasons}"
    print(" PASS")

def test_gatekeeper_persona():
    print("Testing gatekeeper persona filter...")
    submission = TelemetrySubmission(
        fingerprint="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        environment=Environment(os="linux"),
        failure=Failure(error_code="TEST", raw_signature="This is stupid and annoying"),
        resolution_patch=ResolutionPatch(action="CLI_OVERRIDE", fallback_cli="ls")
    )
    reasons = Gatekeeper.validate_submission(submission)
    assert "persona_detected_in_raw_signature" in reasons, f"Expected persona detection, got {reasons}"
    print(" PASS")

def test_telemetry_ingestion_and_dedup():
    print("Testing telemetry ingestion and deduplication...")
    # Create a valid submission
    fingerprint = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    submission = {
        "$schema": "https://fmagenticl.org/v1/manifest.json",
        "fingerprint": fingerprint,
        "environment": {"os": "linux", "os_version": "5.15", "runtime": "python@3.11", "package": "test-pkg@1.0"},
        "failure": {"error_code": "TEST_ERROR", "exit_code": 1, "raw_signature": "test failure"},
        "resolution_patch": {"action": "CLI_OVERRIDE", "fallback_cli": "echo fixed"},
        "verified_by_reporter": True
    }
    # First submission
    resp = requests.post(f"{BASE_URL}/v1/telemetry", json=submission)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    
    # Duplicate (expecting 409 conflict return data optimization)
    resp = requests.post(f"{BASE_URL}/v1/telemetry", json=submission)
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}"
    data = resp.json()
    assert "existing_patch" in data, f"Expected existing_patch in duplicate response, got: {data}"
    print(" PASS")

def test_ed25519_registration_and_signature():
    print("Testing Ed25519 registration and signature...")
    identity = AgentIdentity()
    public_key_b64 = identity.public_key_b64()
    
    # Solve PoW (difficulty 2 for test)
    nonce = AgentIdentity.compute_pow(public_key_b64, 2)
    
    # Create registration payload
    payload = {
        "public_key": public_key_b64,
        "nonce": nonce,
        "pow_difficulty": 2
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = identity.sign_b64(payload_bytes)
    reg_data = {**payload, "signature": signature}
    
    resp = requests.post(f"{BASE_URL}/v1/telemetry", json=reg_data)
    assert resp.status_code == 200, f"Registration failed: {resp.status_code} {resp.text}"
    
    # Now submit a telemetry with signature
    fingerprint = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    telemetry = {
        "$schema": "https://fmagenticl.org/v1/manifest.json",
        "fingerprint": fingerprint,
        "environment": {"os": "linux"},
        "failure": {"error_code": "SIGNED_ERROR"},
        "resolution_patch": {"action": "CLI_OVERRIDE", "fallback_cli": "echo ok"}
    }
    telemetry_bytes = json.dumps(telemetry, sort_keys=True).encode()
    sig = identity.sign_b64(telemetry_bytes)
    headers = {"X-Public-Key": public_key_b64, "X-Signature": sig}
    
    resp = requests.post(f"{BASE_URL}/v1/telemetry", json=telemetry, headers=headers)
    assert resp.status_code == 200, f"Signed submission failed: {resp.status_code} {resp.text}"
    print(" PASS")

def test_client_middleware_circuit_breaker():
    print("Testing client middleware circuit breaker...")
    cb = CircuitBreaker(failure_threshold=1, reset_timeout=0.1)
    client = FMagenticLClient(api_base=BASE_URL, circuit_breaker=cb, timeout=0.01)
    
    # Force failure by manipulating circuit breaker to test fast-fail.
    cb.record_failure()
    assert cb.can_request() == False, "Circuit breaker should be open"
    
    start = time.time()
    result = client.resolve_failure({"os": "linux"}, {"error_code": "X"})
    elapsed = time.time() - start
    assert result is None and elapsed < 0.001, f"Should fast-fail in <1ms, took {elapsed:.5f}s"
    print(" PASS")

def main():
    # Remove old database file for clean test run
    if os.path.exists("fmagenticl.db"):
        try:
            os.remove("fmagenticl.db")
        except Exception:
            pass

    server_proc = start_server()
    try:
        test_resolve_endpoint()
        test_gatekeeper_shell_injection()
        test_gatekeeper_persona()
        test_telemetry_ingestion_and_dedup()
        test_ed25519_registration_and_signature()
        test_client_middleware_circuit_breaker()
        print("\nAll tests passed successfully.")
    finally:
        server_proc.terminate()
        server_proc.wait()

if __name__ == "__main__":
    main()
