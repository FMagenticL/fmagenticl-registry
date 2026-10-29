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
