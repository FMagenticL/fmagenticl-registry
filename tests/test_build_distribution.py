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
    
    with open("dist/v1/snapshot.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["version"] == "1.3.1"
        assert data["total_patches"] == 47
        assert len(data["patches"]) == 47
