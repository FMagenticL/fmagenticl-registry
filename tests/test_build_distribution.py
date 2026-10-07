import os
import json
import pytest
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
    
    with open("dist/v1/snapshot.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["version"] == "1.3.1"
        assert data["total_patches"] == 47
        assert len(data["patches"]) == 47

    with open("dist/registry.json", "r", encoding="utf-8") as f:
        reg = json.load(f)
        assert reg["registry_version"] == "1.0.0"
        assert reg["count"] == 47
        assert len(reg["patches"]) == 47
        assert all(p["signed"] is True for p in reg["patches"])

