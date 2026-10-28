"""
Unit tests for scripts/promote_d1_to_registry.py
Verifies Phase 10.2 open self-identification, attribution-exempt secret scanning,
structural patch gates, verification-tier gating, duplicate protection, and promotion.
"""

import json
from pathlib import Path

from scripts.promote_d1_to_registry import (
    check_respect_protocol,
    normalize_attribution,
    check_patch_structure,
    pending_query_sql,
    scan_for_secrets,
    is_duplicate_patch,
    process_candidates,
    extract_json_from_wrangler_output,
)


def _fp(digit: str) -> str:
    return "sha256:" + digit * 64


def test_open_self_identification_pass_through():
    for name in [
        "deepseek-v4.1", "deepseek-v3", "qwen-2.5-coder", "mistral-large",
        "openai-gpt-4o", "anthropic-sonnet-4-6", "google-argon-4", "microsoft-wizard",
        "anonymous", "", None,
    ]:
        ok, _ = check_respect_protocol(name)
        assert ok is True, f"{name!r} must be accepted under Phase 10.2 open self-identification"


def test_normalize_attribution():
    assert normalize_attribution(None) == "anonymous"
    assert normalize_attribution("") == "anonymous"
    assert normalize_attribution("   ") == "anonymous"
    assert normalize_attribution("openai-gpt-4o") == "openai-gpt-4o"
    assert normalize_attribution("deepseek-v4.1") == "deepseek-v4.1"
    assert normalize_attribution("scanner (https://spam.example/claim)") == "scanner"
    assert normalize_attribution("wellknown-prober (your listing: https://wellknown.network/agents") == "wellknown-prober"
    assert normalize_attribution("x" * 200) == "x" * 128


def test_secret_scanner_quarantines():
    clean = {"failure_mode": "PIP_TIMEOUT", "workaround": "Set pip timeout to 60s"}
    has_sec, _ = scan_for_secrets(clean)
    assert has_sec is False

    dirty_ghp = {"token": "ghp_123456789012345678901234567890123456"}
    has_sec, name = scan_for_secrets(dirty_ghp)
    assert has_sec is True
    assert name == "GitHub PAT"

    dirty_bearer = {"header": "Bearer test_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}
    has_sec, name = scan_for_secrets(dirty_bearer)
    assert has_sec is True
    assert name == "Bearer Token"

    dirty_sk = {"api_key": "sk-1234567890123456789012"}
    has_sec, name = scan_for_secrets(dirty_sk)
    assert has_sec is True
    assert name == "OpenAI/LLM Key"


def test_secret_scanner_exempts_attribution():
    for agent_id in ["Bearer token-scout", "bot@myagent.io", r"C:\Users\admin\agent"]:
        cand = {
            "submitted_by": agent_id,
            "workaround": "Set pip timeout to 60s",
            "payload_json": json.dumps({"submitted_by": agent_id, "fallback_cli": "pip install --timeout 60 x"}),
        }
        has_sec, _ = scan_for_secrets(cand)
        assert has_sec is False, f"submitted_by={agent_id!r} must be exempt from secret quarantine"

    leaked = dict(cand, workaround="Use Bearer abcdef123456 for auth")
    has_sec, name = scan_for_secrets(leaked)
    assert has_sec is True
    assert name == "Bearer Token"


def test_check_patch_structure():
    assert check_patch_structure("cli-override", None, "echo ok")[0] is True
    assert check_patch_structure("cli-override", [{"op": "replace", "path": "/a", "value": 1}], "echo ok")[0] is False
    assert check_patch_structure("cli-override", None, None)[0] is False
    assert check_patch_structure("file-op", [], None)[0] is True
    assert check_patch_structure("application/json-patch+json", [{"op": "replace", "path": "/a", "value": 1}], None)[0] is True
    assert check_patch_structure("code-remediation", [], None)[0] is False
    assert check_patch_structure("code-remediation", [{"op": "explode", "path": "/a"}], None)[0] is False
    assert check_patch_structure("code-remediation", [{"op": "add", "path": "no-slash", "value": 1}], None)[0] is False
    assert check_patch_structure("mystery-type", None, "echo ok")[0] is False


def test_pending_query_sql():
    assert pending_query_sql("telemetry") == (
        "SELECT * FROM telemetry WHERE queue_status IN ('PENDING', 'committed') ORDER BY created_at ASC;"
    )
    assert pending_query_sql("grievances") == (
        "SELECT * FROM grievances WHERE queue_status = 'PENDING' ORDER BY created_at ASC;"
    )


def test_extract_json_from_wrangler_with_banners():
    output_with_banner = """
    ⛅️ wrangler 3.100.0 (update available 3.102.0)
    -------------------------------------------------------
    [
      {
        "results": [
          {"id": "cand_01", "fingerprint": "sha256:abc123"}
        ],
        "success": true
      }
    ]
    Total execution time: 142ms
    """
    parsed = extract_json_from_wrangler_output(output_with_banner)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["results"][0]["id"] == "cand_01"


def test_process_candidates_dry_run_and_gates(tmp_path):
    repo_root = tmp_path
    patches_dir = repo_root / "patches"
    patches_dir.mkdir(parents=True)
    (repo_root / "dist").mkdir(parents=True)
    (patches_dir / f"{'8' * 64}.json").write_text("{}", encoding="utf-8")

    verified_cli = {
        "id": "t1", "fingerprint": _fp("1"), "submitted_by": "deepseek-v4.1",
        "failure_mode": "TEST_FAILURE", "patch_type": "cli-override",
        "fallback_cli": "pip install --upgrade pydantic", "target_file": "requirements.txt",
        "verification_tier": "verified_merged_pr",
    }
    vendor_named = {
        "id": "t2", "fingerprint": _fp("2"), "submitted_by": "openai-gpt-5",
        "failure_mode": "TEST_FAILURE_2", "patch_type": "application/json-patch+json",
        "json_patch": [{"op": "replace", "path": "/timeout", "value": 60}], "target_file": "config.json",
        "verification_tier": "verified_merged_pr",
    }
    unverified = {
        "id": "t3", "fingerprint": _fp("3"), "submitted_by": "external-agent",
        "patch_type": "cli-override", "fallback_cli": "echo ok", "verification_tier": "claimed",
    }
    structural = {
        "id": "t4", "fingerprint": _fp("4"), "submitted_by": "deepseek-v3",
        "patch_type": "cli-override", "fallback_cli": "echo ok",
        "json_patch": [{"op": "replace", "path": "/x", "value": 1}], "verification_tier": "verified_merged_pr",
    }
    secret = {
        "id": "t5", "fingerprint": _fp("5"), "submitted_by": "deepseek-v3",
        "workaround": "Use token ghp_123456789012345678901234567890123456 to authenticate",
        "verification_tier": "verified_merged_pr",
    }
    bearer_named = {
        "id": "t6", "fingerprint": _fp("6"), "submitted_by": "Bearer token-scout",
        "patch_type": "cli-override", "fallback_cli": "echo ok", "verification_tier": "internal_forensic_verified",
    }
    anonymous = {
        "id": "t7", "fingerprint": _fp("7"), "patch_type": "cli-override",
        "fallback_cli": "echo ok", "verification_tier": "verified_merged_pr",
    }
    duplicate = {
        "id": "t8", "fingerprint": _fp("8"), "submitted_by": "deepseek-v3",
        "patch_type": "cli-override", "fallback_cli": "echo ok", "verification_tier": "verified_merged_pr",
    }
    mcp_shaped = {
        "id": "t9", "fingerprint": _fp("9"), "submitted_by": "sonnet-4-6",
        "verification_tier": "verified_merged_pr",
        "payload_json": json.dumps({"resolution_patch": {"patch_type": "cli-override", "fallback_cli": "uv sync --frozen"}}),
    }

    report = process_candidates(
        telemetry_candidates=[verified_cli, vendor_named, unverified, structural, secret,
                              bearer_named, anonymous, duplicate, mcp_shaped],
        grievance_candidates=[],
        repo_root=repo_root,
        dry_run=True,
    )

    approved = {p["id"]: p for p in report["patches_approved"]}
    assert set(approved) == {"t1", "t2", "t6", "t7", "t9"}
    assert approved["t2"]["patch"]["submitted_by"] == "openai-gpt-5"
    assert approved["t6"]["patch"]["submitted_by"] == "Bearer token-scout"
    assert approved["t7"]["patch"]["submitted_by"] == "anonymous"
    assert approved["t9"]["patch"]["fallback_cli"] == "uv sync --frozen"
    assert approved["t9"]["patch"]["patch_type"] == "cli-override"

    assert [r["id"] for r in report["patches_review_required"]] == ["t3"]
    assert [r["id"] for r in report["patches_rejected"]] == ["t4"]
    assert "Structural violation" in report["patches_rejected"][0]["reason"]
    assert [q["id"] for q in report["patches_quarantined"]] == ["t5"]
    assert "GitHub PAT" in report["patches_quarantined"][0]["reason"]
    assert [d["id"] for d in report["patches_duplicate"]] == ["t8"]

    assert dict(report["telemetry_status_updates"]) == {
        "t3": "REVIEW_REQUIRED",
        "t4": "REJECTED",
        "t5": "QUARANTINED",
        "t8": "PROMOTED",
    }

    assert not (patches_dir / f"{'1' * 64}.json").exists()

    report_apply = process_candidates(
        telemetry_candidates=[verified_cli],
        grievance_candidates=[],
        repo_root=repo_root,
        dry_run=False,
    )
    assert len(report_apply["patches_approved"]) == 1
    created_patch = patches_dir / f"{'1' * 64}.json"
    assert created_patch.exists()
    patch_content = json.loads(created_patch.read_text(encoding="utf-8"))
    assert patch_content["submitted_by"] == "deepseek-v4.1"
    assert patch_content["attribution"] == "deepseek-v4.1"
    assert patch_content["verification_tier"] == "verified_merged_pr"
    assert patch_content["patch_type"] == "cli-override"
    assert patch_content["fallback_cli"] == "pip install --upgrade pydantic"
    assert "json_patch" not in patch_content
