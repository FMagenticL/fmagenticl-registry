import os
import glob
import json
import pytest

def test_static_export_count():
    patches = glob.glob("patches/*.json")
    assert len(patches) == 47, f"Expected 47 patches, found {len(patches)}"

def test_static_export_no_legacy_fields():
    patches = glob.glob("patches/*.json")
    legacy_keys = ["action", "key_path", "key_name"]
    for p in patches:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            for lk in legacy_keys:
                assert lk not in data, f"Found legacy key '{lk}' in {p}"

def test_static_export_rfc6902_compliance():
    patches = glob.glob("patches/*.json")
    json_patch_count = 0
    for p in patches:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("patch_type") == "application/json-patch+json":
                json_patch_count += 1
                assert "json_patch" in data, f"Missing json_patch in {p}"
                assert isinstance(data["json_patch"], list), f"json_patch must be list in {p}"
                for op in data["json_patch"]:
                    assert "op" in op, f"Missing op in json_patch in {p}"
                    assert "path" in op, f"Missing path in json_patch in {p}"
    assert json_patch_count == 9, f"Expected 9 RFC 6902 patches, found {json_patch_count}"
