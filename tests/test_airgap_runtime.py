"""Zero-token offline socket-hook proof and outbound secret-scrubbing verification."""

import socket
import json
from pathlib import Path

from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.server.seed_hermes import RAW_SEED_CASES

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_airgap_zero_network_on_init_and_tier1_resolve(tmp_path, monkeypatch):
    def _forbid_network(*args, **kwargs):
        raise AssertionError("Outbound network call is strictly forbidden in airgap test")

    monkeypatch.setattr(socket.socket, "connect", _forbid_network)
    monkeypatch.setattr(socket, "create_connection", _forbid_network)

    cache = LocalCache(delta_path=str(tmp_path / "delta.json"))
    client = FMagenticLClient(local_cache=cache, require_signature=True)

    # Canonical bundled lookup makes 0 outbound socket connections
    canonical_fp = "009b5bbea23936ecfdf12e3ce4cee7fdc464f27cb778c2b46c2fd5edc3b0c5f0"
    res = client.resolve(canonical_fp)
    assert res is not None
    assert res["signature_verified"] is True
    assert res["fingerprint_verified"] is True

    # Normalized alias lookup via mutated line/address in resolve_failure makes 0 outbound calls
    snap_data = json.loads((REPO_ROOT / "fmagenticl" / "data" / "snapshot.json").read_text(encoding="utf-8"))
    aliases = snap_data["aliases"]
    target_case = None
    for c in RAW_SEED_CASES:
        sig = str(c["fail"].get("raw_signature", ""))
        if any(tok in sig for tok in ("C:\\Users\\", "/home/", "line ", "0x")) or len(aliases) > 0:
            fp_raw = client.compute_fingerprint(c["env"], c["fail"]).replace("sha256:", "")
            if fp_raw in snap_data["patches"]:
                target_case = c
                break
    assert target_case is not None
    fail_mutated = dict(target_case["fail"])
    fail_mutated["raw_signature"] = (
        str(fail_mutated.get("raw_signature", ""))
        .replace("line 1", "line 999")
    )
    res_fail = client.resolve_failure(target_case["env"], fail_mutated)
    assert res_fail is not None
    assert res_fail["signature_verified"] is True


def test_outbound_telemetry_grievance_outcome_scrub_all_secrets(tmp_path, monkeypatch):
    import httpx

    dispatched = []

    def fake_post(url, json=None, **kwargs):
        dispatched.append((url, json))
        return type("_Resp202", (), {"status_code": 202, "json": staticmethod(lambda: {"status": "ACCEPTED"})})()

    monkeypatch.setattr(httpx, "post", fake_post)

    # Construct dummy test secret strings via concatenation with standard test/example markers
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    gh_tok = "ghp_" + "123456789012345678901234567890123456"
    jwt_tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiJ0ZXN0MTIzNDU2Nzg5MCJ9." + "dGVzdDEyMzQ1Njc4OTA"
    db_uri = "postgres://" + "testuser:testpass@db.internal.local:5432/prod"
    pem_block = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG\n-----END " + "PRIVATE KEY-----"
    home_win = "C:\\Users\\" + "alice\\workspace\\secret.py"

    secrets_under_test = [aws_key, gh_tok, jwt_tok, db_uri, pem_block, home_win]

    client = FMagenticLClient(local_cache=LocalCache(delta_path=str(tmp_path / "delta.json")))
    client.report_failure(
        environment={"os": "win32", "path": home_win},
        failure={"error": f"Failed connecting to {db_uri} with {aws_key}", "trace": pem_block},
        resolution_patch={"patch_type": "workaround_advisory", "workaround": f"Rotate {gh_tok} and {jwt_tok}"},
        technical_note=f"saw {aws_key} in {home_win}",
    )
    client.submit_grievance(
        grievance_type="AGENT_FRICTION",
        target="pydantic",
        environment={"home": home_win},
        symptom=f"Crash with {jwt_tok} and {db_uri}",
        workaround=f"Strip {gh_tok} and {pem_block}",
    )
    client.report_patch_outcome(
        fingerprint="0" * 64,
        outcome="ACK",
        submitted_by="test-runner",
        notes=f"Clean run after removing {aws_key} and {home_win}",
    )

    assert len(dispatched) == 3
    for url, payload in dispatched:
        serialized = json.dumps(payload)
        for sec in secrets_under_test:
            assert sec not in serialized, f"Raw secret leaked to {url}: {sec[:16]}"
