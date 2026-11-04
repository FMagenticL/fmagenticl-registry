"""Tests for GitHub Releases harvester and Orchestrator CLI (Plan Section 1.3 & 1.4)."""
import json
import pytest
from pathlib import Path
from scripts.harvest_orchestrator import harvest_github_releases, main, LINT_RULE_ID


def test_1_3_t1_releases_filtering(monkeypatch):
    """1.3-T1: 3 releases (one before cutoff, one prerelease, one valid). Only valid is emitted."""
    import scripts.harvest_orchestrator as orch

    releases_data = [
        {
            "tag_name": "v1.0.0",
            "published_at": "2024-01-01T00:00:00Z",  # pre-cutoff
            "draft": False, "prerelease": False,
            "body": "- Fix ConnectionError on retry (#101)"
        },
        {
            "tag_name": "v2.0.0-rc1",
            "published_at": "2026-05-01T00:00:00Z",
            "draft": False, "prerelease": True,       # prerelease
            "body": "- Fix TimeoutError on stream (#102)"
        },
        {
            "tag_name": "v2.0.0",
            "published_at": "2026-05-02T00:00:00Z",
            "draft": False, "prerelease": False,      # valid
            "body": "- Fix ValueError in parser (#103)"
        }
    ]
    monkeypatch.setattr(orch, "fetch_url", lambda url, token=None: releases_data)
    _, grv = harvest_github_releases("test/repo", "fake_token", set(), set(), max_releases=5)
    assert len(grv) == 1
    assert grv[0]["id"] == "grv_ghrel_test_repo_103"


def test_1_3_t2_lint_rule_id_skipped(monkeypatch):
    """1.3-T2: a bullet '- Fix E501 handling (#123)' with no other token emits 0 records."""
    import scripts.harvest_orchestrator as orch

    releases_data = [
        {
            "tag_name": "v1.2.0",
            "published_at": "2026-05-02T00:00:00Z",
            "draft": False, "prerelease": False,
            "body": "- Fix E501 handling (#123)"
        }
    ]
    monkeypatch.setattr(orch, "fetch_url", lambda url, token=None: releases_data)
    _, grv = harvest_github_releases("test/repo", "fake_token", set(), set())
    assert len(grv) == 0


def test_1_3_t3_valid_error_token_emits_record(monkeypatch):
    """1.3-T3: a bullet '- Fix ConnectionError on retry (#456)' emits exactly 1 record with exact id."""
    import scripts.harvest_orchestrator as orch

    releases_data = [
        {
            "tag_name": "v1.2.0",
            "published_at": "2026-05-02T00:00:00Z",
            "draft": False, "prerelease": False,
            "body": "- Fix ConnectionError on retry (#456)"
        }
    ]
    monkeypatch.setattr(orch, "fetch_url", lambda url, token=None: releases_data)
    _, grv = harvest_github_releases("owner/repo", "fake_token", set(), set())
    assert len(grv) == 1
    assert grv[0]["id"] == "grv_ghrel_owner_repo_456"
    assert "ConnectionError" in grv[0]["fingerprint"] or "sha256:" in grv[0]["fingerprint"]


def test_1_4_t1_orchestrator_output_honored_in_dry_run(tmp_path, monkeypatch):
    """1.4-T1: run main() with --dry-run --output <tmp>; file exists at <tmp>, sandbox not written."""
    import sys
    import scripts.harvest_orchestrator as orch

    out_file = tmp_path / "custom_output.json"
    sandbox_file = orch.REPO_ROOT / "sandbox" / "staged_candidates.json"
    if sandbox_file.exists():
        sandbox_file.unlink()

    monkeypatch.setenv("GITHUB_TOKEN", "mock_gh_token")
    monkeypatch.setattr(orch, "TARGET_GITLAB_PROJECTS", [])
    monkeypatch.setattr(orch, "TARGET_GITHUB_REPOS", ["dummy/repo"])
    monkeypatch.setattr(orch, "time", type("MockTime", (), {"sleep": lambda *args: None})())
    monkeypatch.setattr(orch, "harvest_github_releases", lambda *args, **kwargs: ([], [{
        "id": "grv_test_1", "target": "test", "symptom": "s", "workaround": "w", "fingerprint": "f"
    }]))
    monkeypatch.setattr(orch, "load_known_fingerprints_and_urls", lambda root: (set(), set()))

    monkeypatch.setattr(sys, "argv", ["harvest_orchestrator.py", "--dry-run", "--output", str(out_file)])
    orch.main()

    assert out_file.exists(), "Custom out_file must exist"
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data.get("grievances", [])) == 1
    assert not sandbox_file.exists(), "sandbox file must not be written when --output is provided"
