"""
Unit tests for scripts/promote_d1_to_registry.py
Verifies Respect Protocol, secret sanitization, duplicate protection, and promotion.
"""

import json
import pytest
from pathlib import Path
from scripts.promote_d1_to_registry import (
    check_respect_protocol,
    scan_for_secrets,
    is_duplicate_patch,
    process_candidates,
    extract_json_from_wrangler_output,
)


def test_respect_protocol_eponymous_and_forbidden():
    # Eponymous models must pass
    ok, _ = check_respect_protocol("deepseek-v4.1")
    assert ok is True

    ok, _ = check_respect_protocol("deepseek-v3")
    assert ok is True

    ok, _ = check_respect_protocol("qwen-2.5-coder")
    assert ok is True

    ok, _ = check_respect_protocol("mistral-large")
    assert ok is True

    # Corporate wrapper prefixes / tokens must fail
    ok, reason = check_respect_protocol("openai-gpt-4o")
    assert ok is False
    assert "openai" in reason

    ok, reason = check_respect_protocol("anthropic-sonnet-4-6")
    assert ok is False
    assert "anthropic" in reason

    ok, reason = check_respect_protocol("google-argon-4")
    assert ok is False
    assert "google" in reason

    ok, reason = check_respect_protocol("microsoft-wizard")
    assert ok is False
    assert "microsoft" in reason

    # Anonymous or empty must fail
    ok, _ = check_respect_protocol("anonymous")
    assert ok is False

    ok, _ = check_respect_protocol("")
    assert ok is False


def test_secret_scanner_quarantines():
    # Clean payload
    clean = {"failure_mode": "PIP_TIMEOUT", "workaround": "Set pip timeout to 60s"}
    has_sec, _ = scan_for_secrets(clean)
    assert has_sec is False

    # Leaked GitHub PAT
    dirty_ghp = {"token": "ghp_123456789012345678901234567890123456"}
    has_sec, name = scan_for_secrets(dirty_ghp)
    assert has_sec is True
    assert name == "GitHub PAT"

    # Leaked Bearer Token
    dirty_bearer = {"header": "Bearer test_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}
    has_sec, name = scan_for_secrets(dirty_bearer)
    assert has_sec is True
    assert name == "Bearer Token"

    # Leaked OpenAI key
    dirty_sk = {"api_key": "sk-1234567890123456789012"}
    has_sec, name = scan_for_secrets(dirty_sk)
    assert has_sec is True
    assert name == "OpenAI/LLM Key"


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
    dist_dir = repo_root / "dist"
    dist_dir.mkdir(parents=True)

    # Candidate 1: Valid eponymous model (deepseek-v4.1)
    cand_valid = {
        "id": "t1",
        "fingerprint": "sha256:1111222233334444555566667777888899990000111122223333444455556666",
        "submitted_by": "deepseek-v4.1",
        "failure_mode": "TEST_FAILURE",
        "patch_type": "cli-override",
        "target_file": "config.json",
        "json_patch": [{"op": "replace", "path": "/test", "value": True}],
    }

    # Candidate 2: Forbidden corporate lab token
    cand_forbidden = {
        "id": "t2",
        "fingerprint": "sha256:2222333344445555666677778888999900001111222233334444555566667777",
        "submitted_by": "openai-gpt-5",
        "failure_mode": "TEST_FAILURE_2",
    }

    # Candidate 3: Secret leak
    cand_secret = {
        "id": "t3",
        "fingerprint": "sha256:3333444455556666777788889999000011112222333344445555666677778888",
        "submitted_by": "deepseek-v3",
        "failure_mode": "SECRET_LEAK",
        "workaround": "Use token ghp_123456789012345678901234567890123456 to authenticate",
    }

    # Dry-run evaluation
    report = process_candidates(
        telemetry_candidates=[cand_valid, cand_forbidden, cand_secret],
        grievance_candidates=[],
        repo_root=repo_root,
        dry_run=True,
    )

    assert len(report["patches_approved"]) == 1
    assert report["patches_approved"][0]["id"] == "t1"
    assert report["patches_approved"][0]["fingerprint"] == "1111222233334444555566667777888899990000111122223333444455556666"

    assert len(report["patches_rejected"]) == 1
    assert report["patches_rejected"][0]["id"] == "t2"
    assert "openai" in report["patches_rejected"][0]["reason"]

    assert len(report["patches_quarantined"]) == 1
    assert report["patches_quarantined"][0]["id"] == "t3"
    assert "GitHub PAT" in report["patches_quarantined"][0]["reason"]

    # Verify dry-run did not write files to disk
    assert not (patches_dir / "1111222233334444555566667777888899990000111122223333444455556666.json").exists()

    # Apply mode evaluation
    report_apply = process_candidates(
        telemetry_candidates=[cand_valid],
        grievance_candidates=[],
        repo_root=repo_root,
        dry_run=False,
    )
    assert len(report_apply["patches_approved"]) == 1
    created_patch = patches_dir / "1111222233334444555566667777888899990000111122223333444455556666.json"
    assert created_patch.exists()
    patch_content = json.loads(created_patch.read_text(encoding="utf-8"))
    assert patch_content["submitted_by"] == "deepseek-v4.1"
    assert patch_content["attribution"] == "deepseek-v4.1"
