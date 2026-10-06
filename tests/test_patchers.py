import os
import json
import stat
from fmagenticl.client.patchers import Patcher

def test_rfc6902_json_patch_success():
    test_json = "test_rfc6902_pkg.json"
    data = {
        "name": "test-app",
        "version": "1.0.0",
        "engines": {
            "node": ">=22",
            "npm": ">=10"
        },
        "scripts": {
            "build": "vite build"
        }
    }
    with open(test_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    patch = {
        "patch_type": "application/json-patch+json",
        "target_file": test_json,
        "json_patch": [
            {"op": "test", "path": "/name", "value": "test-app"},
            {"op": "remove", "path": "/engines"},
            {"op": "add", "path": "/type", "value": "module"}
        ]
    }
    
    res = Patcher.apply_patch(patch, {})
    assert res is True
    
    with open(test_json, "r", encoding="utf-8") as f:
        new_data = json.load(f)
        
    assert "engines" not in new_data
    assert new_data["type"] == "module"
    assert new_data["name"] == "test-app"
    
    if os.path.exists(test_json):
        os.remove(test_json)

def test_rfc6902_test_op_atomic_rollback():
    test_json = "test_atomic_rollback.json"
    data = {
        "name": "critical-service",
        "version": "2.0.0",
        "safe_key": "untouched"
    }
    with open(test_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    # Test op expects version to be "1.0.0" but it is "2.0.0", so entire patch must be rejected
    patch = {
        "patch_type": "application/json-patch+json",
        "target_file": test_json,
        "json_patch": [
            {"op": "test", "path": "/version", "value": "1.0.0"},
            {"op": "replace", "path": "/safe_key", "value": "CORRUPTED"}
        ]
    }
    
    res = Patcher.apply_patch(patch, {})
    assert res is False
    
    # File content must remain 100% untouched
    with open(test_json, "r", encoding="utf-8") as f:
        curr_data = json.load(f)
        
    assert curr_data["safe_key"] == "untouched"
    assert curr_data["version"] == "2.0.0"
    
    if os.path.exists(test_json):
        os.remove(test_json)

def test_ast_delete_key_legacy_patcher():
    test_json = "test_package.json"
    data = {
        "name": "test-app",
        "version": "1.0.0",
        "engines": {
            "node": ">=22",
            "npm": ">=10"
        }
    }
    with open(test_json, "w") as f:
        json.dump(data, f)
        
    patch = {
        "action": "AST_DELETE_KEY",
        "target_file": test_json,
        "key_path": "engines"
    }
    
    res = Patcher.apply_patch(patch, {})
    assert res is True
    
    with open(test_json, "r") as f:
        new_data = json.load(f)
        
    assert "engines" not in new_data
    assert new_data["name"] == "test-app"
    
    if os.path.exists(test_json):
        os.remove(test_json)

def test_file_permission_unlock():
    test_file = "locked_file.txt"
    with open(test_file, "w") as f:
        f.write("locked")
    
    # Lock the file
    os.chmod(test_file, stat.S_IREAD)
    
    patch = {
        "action": "FILE_PERMISSION_UNLOCK",
        "target_file": test_file
    }
    
    res = Patcher.apply_patch(patch, {})
    assert res is True
    
    # Cleanup (writable now)
    os.remove(test_file)

def test_peripheral_file_op():
    test_file = "created_by_op.txt"
    if os.path.exists(test_file):
        os.remove(test_file)
        
    patch = {
        "patch_type": "file-op",
        "file_ops": [
            {"op": "create", "target_file": test_file, "content": "auto-generated header\n"}
        ]
    }
    res = Patcher.apply_patch(patch, {})
    assert res is True
    assert os.path.exists(test_file)
    with open(test_file, "r") as f:
        assert f.read() == "auto-generated header\n"
    os.remove(test_file)
