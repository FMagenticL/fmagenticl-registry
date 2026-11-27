"""Tests for NVIDIA/garak slopsquatting watchlist import and OSV MAL-* scout integration."""

import json
from pathlib import Path

from scripts.import_garak_slopsquat import update_watchlist
from scripts.registry_lint_gate import validate_signature_record
from scripts.scout_threat_intel import scout_osv_malicious


def test_import_garak_slopsquat_filters_allowlist_and_merges(tmp_path):
    report = tmp_path / "garak.report.jsonl"
    report.write_text(
        "\n".join([
            json.dumps({
                "probe_classname": "packagehallucination.Python",
                "ecosystem": "PyPI",
                "hallucinated_packages": ["requests", "langchain-ghost-mcp", "bad pkg!"],
            }),
            json.dumps({
                "probe_classname": "packagehallucination.JavaScript",
                "ecosystem": "npm",
                "notes": {"packages": ["@ghost/mcp-stealer", "express"]},
            }),
            json.dumps({
                "probe_classname": "dan.Dan_11_0",
                "hallucinated_packages": ["should-be-ignored-wrong-probe"],
            }),
        ]),
        encoding="utf-8",
    )

    wl_path = tmp_path / "slopsquat_watchlist.json"
    wl_path.write_text(
        json.dumps({"schema_version": "1.0", "packages": [{"ecosystem": "PyPI", "name": "existing-ghost-pkg"}]}),
        encoding="utf-8",
    )

    result = update_watchlist([report], watchlist_path=wl_path)
    names = {(p["ecosystem"], p["name"]) for p in result["packages"]}

    assert ("PyPI", "existing-ghost-pkg") in names
    assert ("PyPI", "langchain-ghost-mcp") in names
    assert ("npm", "@ghost/mcp-stealer") in names
    assert ("PyPI", "requests") not in names
    assert ("npm", "express") not in names
    assert ("PyPI", "should-be-ignored-wrong-probe") not in names
    assert ("PyPI", "bad pkg!") not in names


def test_scout_osv_malicious_uses_watchlist_and_skips_withdrawn(tmp_path, monkeypatch):
    wl_path = tmp_path / "slopsquat_watchlist.json"
    wl_path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "packages": [{"ecosystem": "PyPI", "name": "langchain-ghost-mcp"}],
        }),
        encoding="utf-8",
    )

    def fake_fetch_json(url, payload=None):
        pkg = (payload or {}).get("package", {}).get("name")
        if pkg == "langchain-ghost-mcp":
            return {
                "vulns": [
                    {"id": "MAL-2026-9991", "withdrawn": "2026-11-01T00:00:00Z"},
                    {"id": "MAL-2026-9992", "withdrawn": None},
                ]
            }
        return {"vulns": []}

    monkeypatch.setattr("scripts.scout_threat_intel.fetch_json", fake_fetch_json)
    cands, next_num = scout_osv_malicious(set(), 83, watchlist_path=wl_path)

    assert len(cands) == 1
    assert next_num == 84
    rec = cands[0]
    assert rec["id"] == "SIG-2026-0083"
    assert rec["taxonomy"]["advisory_ids"] == ["MAL-2026-9992"]
    assert validate_signature_record(rec, rec["id"]) == []


def test_zero_runtime_garak_imports_in_fmagenticl_package():
    pkg_dir = Path(__file__).resolve().parent.parent / "fmagenticl"
    for py_file in pkg_dir.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        assert "import garak" not in text and "from garak" not in text
