import json
import os
from fmagenticl import __version__
from scripts.build_distribution import build


def test_build_distribution_execution(tmp_path):
    out_dir = tmp_path / "dist"
    build(output_dir=out_dir, sync_pkg_data=False)

    assert (out_dir / "v1" / "snapshot.json").exists()
    assert (out_dir / "v1" / "keyring.json").exists()
    assert (out_dir / "v1" / "bloom.bin").exists()
    assert (out_dir / "registry.json").exists()
    assert (out_dir / ".well-known" / "agent.json").exists()
    assert (out_dir / ".well-known" / "mcp.json").exists()
    assert (out_dir / "404.html").exists()
    assert (out_dir / "_routes.json").exists()
    assert (out_dir / "_headers").exists()

    routes_data = json.loads((out_dir / "_routes.json").read_text(encoding="utf-8"))
    assert routes_data.get("version") == 1
    assert "/mcp" in routes_data.get("include", [])
    assert "/v1/health" in routes_data.get("exclude", [])
    assert "/v1/keyring.json" in routes_data.get("exclude", [])

    data = json.loads((out_dir / "v1" / "snapshot.json").read_text(encoding="utf-8"))
    assert data["version"] == __version__
    assert data["total_signatures"] >= 60
    assert len(data["signatures_by_id"]) == data["total_signatures"]
    assert len(data["patches"]) == data["total_signatures"]
    assert isinstance(data.get("aliases"), dict) and len(data["aliases"]) >= data["total_signatures"]

    health = json.loads((out_dir / "v1" / "health").read_text(encoding="utf-8"))
    assert health["protocol_version"] == __version__
    assert health["total_entries"] == data["total_signatures"]
    assert health["confirmed_signatures"] >= 45
    assert health["behavioral_indicators"] >= 15

    reg = json.loads((out_dir / "registry.json").read_text(encoding="utf-8"))
    assert reg["registry_version"] == __version__
    assert reg["count"] == data["total_signatures"]
    assert len(reg["signatures"]) == data["total_signatures"]
