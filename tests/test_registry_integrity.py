"""Deterministic v3.0.0 data hygiene, version parity, and Patcher safety gates."""

import json
from pathlib import Path

from fmagenticl import __version__
from scripts.registry_lint_gate import validate_directory

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_signatures_zero_poison_and_valid_schema():
    count, errors = validate_directory(REPO_ROOT / "signatures")
    assert count == 60
    assert errors == []


def test_health_census_and_version_parity_3_0_0():
    assert __version__ == "3.0.0"
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "3.0.0"' in pyproject

    pkg_js = json.loads((REPO_ROOT / "packages" / "client" / "package.json").read_text(encoding="utf-8"))
    assert pkg_js["version"] == "3.0.0"

    srv = json.loads((REPO_ROOT / "server.json").read_text(encoding="utf-8"))
    assert srv["version"] == "3.0.0"

    health = json.loads((REPO_ROOT / "dist" / "v1" / "health").read_text(encoding="utf-8"))
    assert health["protocol_version"] == "3.0.0"
    assert health["total_entries"] == 60
    assert health["confirmed_signatures"] == 45
    assert health["behavioral_indicators"] == 15

    mcp_wellknown = json.loads((REPO_ROOT / "dist" / ".well-known" / "mcp.json").read_text(encoding="utf-8"))
    assert mcp_wellknown["version"] == "3.0.0"
    assert len(mcp_wellknown["tools"]) == 3
