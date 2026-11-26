import json
import os
from fmagenticl import __version__
from scripts.build_distribution import build


def test_build_distribution_execution():
    build()

    assert os.path.exists("dist/v1/snapshot.json")
    assert os.path.exists("dist/v1/keyring.json")
    assert os.path.exists("dist/v1/bloom.bin")
    assert os.path.exists("dist/registry.json")
    assert os.path.exists("dist/.well-known/agent.json")
    assert os.path.exists("dist/.well-known/mcp.json")
    assert os.path.exists("dist/404.html")
    assert os.path.exists("dist/_routes.json")
    assert os.path.exists("dist/_headers")

    with open("dist/_routes.json", "r", encoding="utf-8") as f:
        routes_data = json.load(f)
        assert routes_data.get("version") == 1
        assert "/mcp" in routes_data.get("include", [])
        assert "/v1/health" in routes_data.get("exclude", [])
        assert "/v1/keyring.json" in routes_data.get("exclude", [])

    with open("dist/v1/snapshot.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["version"] == __version__
        assert data["total_signatures"] == 60
        assert len(data["signatures_by_id"]) == 60
        assert len(data["patches"]) == 60
        assert isinstance(data.get("aliases"), dict) and len(data["aliases"]) >= 60

    with open("dist/v1/health", "r", encoding="utf-8") as f:
        health = json.load(f)
        assert health["protocol_version"] == __version__
        assert health["total_entries"] == 60
        assert health["confirmed_signatures"] == 45
        assert health["behavioral_indicators"] == 15

    with open("dist/registry.json", "r", encoding="utf-8") as f:
        reg = json.load(f)
        assert reg["registry_version"] == __version__
        assert reg["count"] == 60
        assert len(reg["signatures"]) == 60
