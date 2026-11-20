import os
import json
import pytest
from fmagenticl import __version__
from scripts.build_distribution import build


def test_build_distribution_execution():
    # Build should succeed even without signing key
    build()

    assert os.path.exists("dist/v1/snapshot.json")
    assert os.path.exists("dist/v1/bloom.bin")
    assert os.path.exists("dist/v1/deltas/latest.json")
    assert os.path.exists("dist/registry.json")
    assert os.path.exists("dist/robots.txt")
    assert os.path.exists("dist/sitemap.xml")
    assert os.path.exists("dist/_redirects")
    assert os.path.exists("dist/.well-known/agent.json")
    assert os.path.exists("dist/404.html")
    assert os.path.exists("dist/_routes.json")

    with open("dist/_routes.json", "r", encoding="utf-8") as f:
        routes_data = json.load(f)
        assert routes_data.get("version") == 1
        assert "/mcp" in routes_data.get("include", [])
        assert "/v1/health" in routes_data.get("exclude", [])

    from fmagenticl.client.verify import verify_patch_envelope

    with open("dist/v1/snapshot.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["version"] == __version__
        assert data["total_patches"] >= 47
        assert len(data["patches"]) >= 47
        assert isinstance(data.get("aliases"), dict) and len(data["aliases"]) >= 40
        for fp_hex, patch_obj in data["patches"].items():
            assert verify_patch_envelope(patch_obj, expected_fingerprint=fp_hex, enforce_expiry=True)

    with open("dist/v1/health", "r", encoding="utf-8") as f:
        health = json.load(f)
        assert health["protocol_version"] == __version__
        assert health["compiled_patches"] == 85
        assert health["executable_patches"] == 54
        assert health["advisory_patches"] == 31
        assert health["executable_patches"] + health["advisory_patches"] == health["compiled_patches"]

    with open("dist/registry.json", "r", encoding="utf-8") as f:
        reg = json.load(f)
        assert reg["registry_version"] == "1.0.0"
        assert reg["count"] >= 47
        assert len(reg["patches"]) >= 47
        assert all(p["signed"] is True for p in reg["patches"])


def test_2_t1_static_shards_generation():
    """Plan 2-T1: dist/shards/workarounds/_recent.json exists with count <= 100 and per-target shards match."""
    import scripts.build_distribution as bd
    import re

    bd.build()

    shard_dir = bd.REPO_ROOT / "dist" / "shards" / "workarounds"
    recent_file = shard_dir / "_recent.json"
    assert recent_file.exists(), "_recent.json must exist in shards"
    recent_data = json.loads(recent_file.read_text(encoding="utf-8"))
    assert recent_data["count"] <= 100

    wrk_file = bd.REPO_ROOT / "dist" / "workarounds.json"
    assert wrk_file.exists()
    all_wrk = json.loads(wrk_file.read_text(encoding="utf-8")).get("workarounds", [])

    def _shard_key(s: str) -> str:
        return re.sub(r"[^a-z0-9._-]", "_", (s or "").strip().lower().replace("/", "__"))[:120]

    for item in all_wrk[:30]:
        tgt = item.get("target")
        if tgt:
            sk = _shard_key(tgt)
            s_file = shard_dir / f"{sk}.json"
            assert s_file.exists(), f"Shard file {s_file} missing for target {tgt}"
            s_data = json.loads(s_file.read_text(encoding="utf-8"))
            s_ids = {x.get("id") for x in s_data.get("workarounds", [])}
            assert item.get("id") in s_ids
