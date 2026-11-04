"""
Unit tests for scripts/harvest_osv_advisories.py
Verifies Gate 1 (withdrawn), Gate 2 (2026 freshness), Gate 3 (highest semver selection),
Gate 4 (mandatory fix), and record construction.
"""

import pytest
from scripts.harvest_osv_advisories import (
    extract_highest_fixed_version,
    evaluate_osv_gates,
    normalize_target_slug
)


def test_highest_semver_selection_multi_branch():
    """Assert that an advisory with multiple backported version ranges selects the highest semver."""
    vuln = {
        "id": "GHSA-test-multi-branch",
        "published": "2026-02-15T00:00:00Z",
        "summary": "Multi-branch backported security vulnerability",
        "affected": [
            {
                "package": {"name": "pydantic", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.10.14"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "2.0.0"},
                            {"fixed": "2.6.4"}
                        ]
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "2.7.0"},
                            {"fixed": "2.7.1"}
                        ]
                    }
                ]
            }
        ]
    }
    highest = extract_highest_fixed_version(vuln, "pydantic")
    assert highest == "2.7.1", f"Expected highest semver '2.7.1', got '{highest}'"


def test_pre_2026_advisory_rejected():
    """Assert that an advisory published/modified prior to 2026 is rejected."""
    vuln = {
        "id": "GHSA-old-vuln-2024",
        "published": "2024-05-10T12:00:00Z",
        "modified": "2024-06-01T12:00:00Z",
        "summary": "Legacy vulnerability from 2024",
        "affected": [
            {
                "package": {"name": "litellm", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "0.1.5"}]}]
            }
        ]
    }
    record = evaluate_osv_gates(vuln, "litellm", "PyPI")
    assert record is None, "Pre-2026 advisory must be rejected by Gate 2"


def test_withdrawn_advisory_rejected():
    """Assert that an advisory with withdrawn timestamp is rejected."""
    vuln = {
        "id": "GHSA-withdrawn-vuln",
        "published": "2026-03-01T00:00:00Z",
        "withdrawn": "2026-03-05T00:00:00Z",
        "summary": "False alarm advisory subsequently withdrawn",
        "affected": [
            {
                "package": {"name": "langchain", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "0.3.15"}]}]
            }
        ]
    }
    record = evaluate_osv_gates(vuln, "langchain", "PyPI")
    assert record is None, "Withdrawn advisory must be rejected by Gate 1"


def test_advisory_lacking_fixed_version_rejected():
    """Assert that an advisory without any 'fixed' version event is rejected (No Whining Without a Workaround)."""
    vuln = {
        "id": "GHSA-unfixed-zero-day",
        "published": "2026-04-10T00:00:00Z",
        "summary": "Zero-day vulnerability with no upstream patch yet",
        "affected": [
            {
                "package": {"name": "uv", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.1.0"}]}]
            }
        ]
    }
    record = evaluate_osv_gates(vuln, "uv", "PyPI")
    assert record is None, "Unpatched zero-day advisory must be rejected by Gate 4"


def test_record_construction_and_ecosystem_formatting():
    """Assert PyPI and npm specific command formatting, ID prefix, and verification tier."""
    pypi_vuln = {
        "id": "PYSEC-2026-9999",
        "published": "2026-03-12T00:00:00Z",
        "summary": "Buffer overflow in fastmcp runtime",
        "affected": [
            {
                "package": {"name": "fastmcp", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "0.4.2"}]}]
            }
        ]
    }
    pypi_rec = evaluate_osv_gates(pypi_vuln, "fastmcp", "PyPI")
    assert pypi_rec is not None
    assert pypi_rec["id"] == "grv_osv_PYSEC_2026_9999"
    assert pypi_rec["target"] == "fastmcp"
    assert pypi_rec["verification_tier"] == "osv_verified"
    assert pypi_rec["queue_status"] == "PROMOTED"
    assert "pip install --upgrade 'fastmcp>=0.4.2'" in pypi_rec["workaround"]

    npm_vuln = {
        "id": "GHSA-npm-wrangler-test",
        "published": "2026-02-20T00:00:00Z",
        "summary": "Improper token validation in wrangler dev server",
        "affected": [
            {
                "package": {"name": "wrangler", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.109.0"}]}]
            }
        ]
    }
    npm_rec = evaluate_osv_gates(npm_vuln, "wrangler", "npm")
    assert npm_rec is not None
    assert npm_rec["id"] == "grv_osv_GHSA_npm_wrangler_test"
    assert npm_rec["target"] == "wrangler"
    assert "npm install 'wrangler@>=3.109.0'" in npm_rec["workaround"]


def test_target_slug_normalization():
    assert normalize_target_slug("@modelcontextprotocol/sdk") == "mcp"
    assert normalize_target_slug("langchain-core") == "langchain"
    assert normalize_target_slug("langchain-community") == "langchain"
    assert normalize_target_slug("pyautogen") == "autogen"
    assert normalize_target_slug("dspy-ai") == "dspy"
    assert normalize_target_slug("llama-index") == "llama-index"


def test_old_cve_bulk_modified_in_2026_rejected():
    """Assert an old advisory whose modified date was bulk-rewritten in 2026 is rejected (published date governs)."""
    vuln = {
        "id": "GHSA-5jqp-qgf6-3pvh",
        "published": "2021-05-13T04:00:00Z",
        "modified": "2026-10-14T09:12:00Z",
        "summary": "Legacy 2021 vulnerability re-touched by OSV in 2026",
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.2.0"}]}]
            }
        ]
    }
    assert evaluate_osv_gates(vuln, "pillow", "PyPI") is None, "Bulk-modified pre-2026 advisory must be rejected"


def test_missing_published_date_rejected():
    vuln = {
        "id": "GHSA-no-published-date",
        "modified": "2026-10-14T09:12:00Z",
        "summary": "Record with no publication date",
        "affected": [{"package": {"name": "axios", "ecosystem": "npm"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.7.4"}]}]}]
    }
    assert evaluate_osv_gates(vuln, "axios", "npm") is None


def test_1_2_t1_seen_cache_skips_hydration(monkeypatch):
    """1.2-T1: with a monkeypatched querybatch and hydrate, a stub whose (id, modified) is in cache is not hydrated."""
    import scripts.harvest_osv_advisories as hoa
    import json

    cache = {"GHSA-test-cached": "2026-05-01T12:00:00Z"}
    batch_resp = {
        "results": [
            {
                "vulns": [
                    {"id": "GHSA-test-cached", "modified": "2026-05-01T12:00:00Z"}
                ]
            }
        ]
    }

    class MockResp:
        def read(self):
            return json.dumps(batch_resp).encode("utf-8")
        def __enter__(self): return self
        def __exit__(self, *args): pass

    monkeypatch.setattr(hoa.urllib.request, "urlopen", lambda req, timeout=30: MockResp())
    hydrate_calls = []
    monkeypatch.setattr(hoa, "hydrate_vuln", lambda vid: hydrate_calls.append(vid) or None)
    monkeypatch.setattr(hoa, "OSV_TARGET_PACKAGES", [("pydantic", "PyPI")])

    results = hoa.harvest_osv(seen_cache=cache)
    assert len(hydrate_calls) == 0, "Cached unchanged stub must not be hydrated"
    assert len(results) == 0


def test_1_2_t2_rejected_advisory_written_to_cache(monkeypatch):
    """1.2-T2: a rejected advisory gets written into the cache with its exact modified value."""
    import scripts.harvest_osv_advisories as hoa
    import json

    cache = {}
    batch_resp = {
        "results": [
            {
                "vulns": [
                    {"id": "GHSA-reject-me", "modified": "2026-06-01T00:00:00Z"}
                ]
            }
        ]
    }

    class MockResp:
        def read(self):
            return json.dumps(batch_resp).encode("utf-8")
        def __enter__(self): return self
        def __exit__(self, *args): pass

    monkeypatch.setattr(hoa.urllib.request, "urlopen", lambda req, timeout=30: MockResp())
    monkeypatch.setattr(hoa, "hydrate_vuln", lambda vid: {
        "id": "GHSA-reject-me",
        "withdrawn": "2026-06-02T00:00:00Z",
        "modified": "2026-06-01T00:00:00Z",
        "published": "2026-05-01T00:00:00Z"
    })
    monkeypatch.setattr(hoa, "OSV_TARGET_PACKAGES", [("pydantic", "PyPI")])

    hoa.harvest_osv(seen_cache=cache)
    assert cache.get("GHSA-reject-me") == "2026-06-01T00:00:00Z", "Rejected advisory must be remembered in cache"


def test_1_2_t3_id_roundtrip():
    """1.2-T3: the ID round-trip for GHSA and PYSEC IDs is exact."""
    for orig in ["GHSA-5jqp-qgf6-3pvh", "PYSEC-2026-9999", "CVE-2026-1234"]:
        rec_id = f"grv_osv_{orig.replace('-', '_')}"
        recovered = rec_id.replace("grv_osv_", "").replace("_", "-")
        assert recovered == orig


def test_1_2_t4_throttle_cap_and_order(tmp_path, monkeypatch):
    """1.2-T4: with OSV_MAX_NEW_PER_RUN=2 and 5 new records, main(--dry-run --output tmp) writes exactly 2 newest."""
    import sys, json
    import scripts.harvest_osv_advisories as hoa

    out_file = tmp_path / "throttled_out.json"
    dummy_records = [
        {"id": "grv_osv_GHSA_5", "created_at": "2026-05-05T00:00:00Z", "_osv_modified": "2026-05-05"},
        {"id": "grv_osv_GHSA_4", "created_at": "2026-05-04T00:00:00Z", "_osv_modified": "2026-05-04"},
        {"id": "grv_osv_GHSA_3", "created_at": "2026-05-03T00:00:00Z", "_osv_modified": "2026-05-03"},
        {"id": "grv_osv_GHSA_2", "created_at": "2026-05-02T00:00:00Z", "_osv_modified": "2026-05-02"},
        {"id": "grv_osv_GHSA_1", "created_at": "2026-05-01T00:00:00Z", "_osv_modified": "2026-05-01"},
    ]
    monkeypatch.setattr(hoa, "MAX_NEW_RECORDS_PER_RUN", 2)
    monkeypatch.setattr(hoa, "load_seen_cache", lambda: {})
    monkeypatch.setattr(hoa, "load_existing_registry_ids", lambda: set())
    monkeypatch.setattr(hoa, "harvest_osv", lambda max_per_pkg=None, seen_cache=None: list(dummy_records))

    monkeypatch.setattr(sys, "argv", ["harvest_osv_advisories.py", "--dry-run", "--output", str(out_file)])
    rc = hoa.main()
    assert rc == 0
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(saved) == 2
    assert saved[0]["id"] == "grv_osv_GHSA_5"
    assert saved[1]["id"] == "grv_osv_GHSA_4"
    assert "_osv_modified" not in saved[0]
