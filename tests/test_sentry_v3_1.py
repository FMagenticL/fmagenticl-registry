import json
from pathlib import Path
import pytest

from scripts.fetch_cf_analytics import classify_error_path
import scripts.run_90min_telemetry as sentry


def test_classify_error_path_buckets():
    # Bucket A: Dynamic runtime (/mcp, /mcp/server-card, /v1/* dynamic, /health)
    assert classify_error_path("/mcp") == "bucket_a_runtime"
    assert classify_error_path("/mcp/server-card") == "bucket_a_runtime"
    assert classify_error_path("/v1/grievance") == "bucket_a_runtime"
    assert classify_error_path("/v1/telemetry") == "bucket_a_runtime"
    assert classify_error_path("/health") == "bucket_a_runtime"

    # Bucket B: Core static CDN (/v1/health, /workarounds.json, /shards/*, /.well-known/*, /mcp/.well-known/oauth-*)
    assert classify_error_path("/v1/health") == "bucket_b_static"
    assert classify_error_path("/workarounds.json") == "bucket_b_static"
    assert classify_error_path("/shards/workarounds/_recent.json") == "bucket_b_static"
    assert classify_error_path("/.well-known/agent-card.json") == "bucket_b_static"
    assert classify_error_path("/mcp/.well-known/oauth-protected-resource") == "bucket_b_static"
    assert classify_error_path("/mcp/.well-known/oauth-authorization-server") == "bucket_b_static"
    assert classify_error_path("/llms.txt") == "bucket_b_static"

    # Bucket C: Unmapped scanner noise (including arbitrary /mcp/* subpaths)
    assert classify_error_path("/a131c452f3a08d3c89206e2b8fdb5908") == "bucket_c_scanner"
    assert classify_error_path("/mcp/random-probe") == "bucket_c_scanner"
    assert classify_error_path("/sw.js") == "bucket_c_scanner"
    assert classify_error_path("/wp-admin/setup-config.php") == "bucket_c_scanner"


def test_audit_workarounds_semantic_and_content_gates(tmp_path, monkeypatch):
    monkeypatch.setattr(sentry, "SCRATCH_DIR", tmp_path)
    monkeypatch.setattr(sentry, "STATE_CACHE", tmp_path / ".last_workarounds_state.json")
    monkeypatch.setattr(sentry, "SHA256_CACHE", tmp_path / ".last_workarounds_sha256")

    # 1. Valid payload passes with 0 violations
    clean_payload = {
        "workarounds": [
            {
                "id": "grv_osv_GHSA_2026_0001",
                "target": "aiohttp",
                "verification_tier": "osv_verified",
                "created_at": "2026-05-10T00:00:00Z",
                "symptom": "HTTP request smuggling in aiohttp parser",
                "workaround": "Upgrade aiohttp to >= 3.10.2 to resolve parser framing issue.",
            }
        ]
    }
    info, violations = sentry.audit_workarounds_payload(json.dumps(clean_payload).encode("utf-8"))
    assert violations == []
    assert info["pre2026_osv_count"] == 0
    assert info["semantic_defect_count"] == 0

    # 2. Historical D1 pagination backfill (>6h old created_at) does NOT trip single-target flood guard
    backfill_items = list(clean_payload["workarounds"])
    for idx in range(50):
        backfill_items.append({
            "id": f"grv_hist_backfill_{idx}",
            "target": "langchain",
            "verification_tier": "verified_release",
            "created_at": "2026-06-15T12:00:00Z",
            "symptom": f"Historical LangChain serialization mismatch #{idx}",
            "workaround": "Upgrade langchain-core to >= 0.3.15 to resolve model_dump schema mismatch.",
        })
    info_bf, violations_bf = sentry.audit_workarounds_payload(
        json.dumps({"workarounds": backfill_items}).encode("utf-8")
    )
    assert violations_bf == []
    assert info_bf["count"] == 51

    # 3. Defective payload catches pre-2026 OSV, npm redaction corruption, and broken version / git SHA
    (tmp_path / ".last_workarounds_state.json").unlink(missing_ok=True)
    (tmp_path / ".last_workarounds_sha256").unlink(missing_ok=True)
    bad_payload = {
        "workarounds": [
            {
                "id": "grv_osv_GHSA_2022_9999",
                "target": "oldpkg",
                "verification_tier": "osv_verified",
                "created_at": "2022-11-01T00:00:00Z",
                "symptom": "Legacy CVE",
                "workaround": "Upgrade oldpkg to >= 1.2.0 immediately.",
            },
            {
                "id": "grv_ghrel_scope_test_1",
                "target": "@scope/pkg",
                "verification_tier": "verified_release",
                "created_at": "2026-06-01T00:00:00Z",
                "symptom": "Crash in @scope/pkg@[REDACTED_EMAIL]",
                "workaround": "Upgrade @scope/pkg to None to fix the issue.",
            },
        ]
    }
    info2, violations2 = sentry.audit_workarounds_payload(json.dumps(bad_payload).encode("utf-8"))
    assert info2["pre2026_osv_count"] == 1
    assert info2["npm_corrupted_count"] == 1
    assert info2["semantic_defect_count"] == 1
    assert len(violations2) == 3
    assert any("Pre-2026" in v for v in violations2)


def test_probation_state_machine_full_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(sentry, "SCRATCH_DIR", tmp_path)
    monkeypatch.setattr(sentry, "PROBATION_STATE_FILE", tmp_path / ".sentry_probation_state.json")

    base_summary = {"hist": {"mcp_504": 5, "bucket_a_5xx_crash": 0}}

    # Step 0: Normal green run -> 5400s
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule([], set(), [], base_summary)
    assert sec == 5400
    assert mode == "STANDARD_90M_HIBERNATION"
    assert dossier is None

    # Step 1: Autonomous fix occurs -> enters Stage 1 (180s / T+3m)
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule(
        [], set(), ["Auto-synchronized local dist/"], base_summary
    )
    assert sec == 180
    assert "PROBATION_STAGE_1" in mode
    assert sentry.load_probation_state()["probation_stage"] == 1

    # Step 2: Stage 1 passes -> advances to Stage 2 (720s / T+15m)
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule([], set(), [], base_summary)
    assert sec == 720
    assert "PROBATION_STAGE_2" in mode
    assert sentry.load_probation_state()["probation_stage"] == 2

    # Step 3: Stage 2 passes -> advances to Stage 3 (1800s / T+45m)
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule([], set(), [], base_summary)
    assert sec == 1800
    assert "PROBATION_STAGE_3" in mode
    assert sentry.load_probation_state()["probation_stage"] == 3

    # Step 4: Stage 3 passes -> graduates back to 5400s (Stage 0)
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule([], set(), [], base_summary)
    assert sec == 5400
    assert mode == "PROBATION_GRADUATED_STANDARD_90M_HIBERNATION"
    assert sentry.load_probation_state()["probation_stage"] == 0


def test_probation_failure_trips_circuit_breaker_and_generates_dossier(tmp_path, monkeypatch):
    monkeypatch.setattr(sentry, "SCRATCH_DIR", tmp_path)
    monkeypatch.setattr(sentry, "PROBATION_STATE_FILE", tmp_path / ".sentry_probation_state.json")

    base_summary = {"hist": {"mcp_504": 5, "bucket_a_5xx_crash": 0}}
    # Enter Stage 1
    sentry.evaluate_probation_and_next_schedule([], set(), ["Tier 2 Fix"], base_summary)

    # Simulate Bucket A 500 crash during Stage 1 probation
    crash_summary = {"hist": {"mcp_504": 5, "bucket_a_5xx_crash": 1}}
    sec, mode, dossier = sentry.evaluate_probation_and_next_schedule([], set(), [], crash_summary)
    assert "PROBATION_STAGE_1_FAILED_CIRCUIT_BREAKER_TRIPPED" in mode
    assert dossier is not None
    assert Path(dossier).exists()
    state = sentry.load_probation_state()
    assert state["circuit_breaker_tripped"] is True
    assert state["probation_stage"] == 0


def test_middleware_mcp_oauth_200_and_fast404():
    import subprocess
    repo_root = Path(__file__).resolve().parent.parent
    esm = r"""
    import { onRequest } from './functions/_middleware.js';
    let nextCalled = 0;
    const mkCtx = (path) => ({
      request: new Request('https://fmagenticl-registry.pages.dev' + path),
      next: async () => { nextCalled += 1; return new Response('NEXT_OK', { status: 200 }); }
    });
    const rAuth = await onRequest(mkCtx('/mcp/.well-known/oauth-authorization-server'));
    const rProt = await onRequest(mkCtx('/mcp/.well-known/oauth-protected-resource'));
    const rCard = await onRequest(mkCtx('/mcp/server-card'));
    const rScan = await onRequest(mkCtx('/mcp/random-scanner-probe'));
    const rMcp  = await onRequest(mkCtx('/mcp'));
    console.log(JSON.stringify({
      authStatus: rAuth.status,
      protStatus: rProt.status,
      cardVer: (await rCard.json()).version,
      scanStatus: rScan.status,
      mcpStatus: rMcp.status,
      nextCalled
    }));
    """
    res = subprocess.run(["node", "--input-type=module", "-e", esm], cwd=str(repo_root), capture_output=True, text=True, timeout=15)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip())
    assert out["authStatus"] == 200
    assert out["protStatus"] == 200
    assert out["cardVer"] == "1.4.1"
    assert out["scanStatus"] == 404
    assert out["mcpStatus"] == 200
    # Only /mcp should invoke context.next() (1 time); oauth-*, server-card, and /mcp/random-scanner-probe NEVER hit context.next()!
    assert out["nextCalled"] == 1
