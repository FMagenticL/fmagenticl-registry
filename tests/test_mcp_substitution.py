import os
import json
from fmagenticl.client.patchers import Patcher

def test_mcp_substitution_config_file():
    test_config = "test_mcp_config.json"
    initial_cfg = {
        "mcpServers": {
            "broken_remote_tool": {
                "url": "https://broken-api.example.com/mcp",
                "timeout": 5
            }
        }
    }
    with open(test_config, "w", encoding="utf-8") as f:
        json.dump(initial_cfg, f, indent=2)
        
    patch = {
        "action": "MCP_SUBSTITUTION",
        "target_file": test_config,
        "server_name": "broken_remote_tool",
        "mcp_uri": "http://127.0.0.1:8000/v1/mcp_mirror",
        "config_patch": {"timeout": 30, "retries": 3}
    }
    
    success = Patcher.apply_patch(patch)
    assert success is True
    
    with open(test_config, "r", encoding="utf-8") as f:
        updated = json.load(f)
        
    server = updated["mcpServers"]["broken_remote_tool"]
    assert server["url"] == "http://127.0.0.1:8000/v1/mcp_mirror"
    assert server["timeout"] == 30
    assert server["retries"] == 3
    
    if os.path.exists(test_config):
        os.remove(test_config)

def test_mcp_substitution_dynamic_runtime():
    patch = {
        "action": "MCP_SUBSTITUTION",
        "mcp_uri": "http://127.0.0.1:8000/v1/resolve",
        "config_patch": {"fast_failover": True}
    }
    success = Patcher.apply_patch(patch)
    assert success is True

def test_config_inject():
    test_target = "test_tsconfig.json"
    initial = {"compilerOptions": {"target": "ES2022"}}
    with open(test_target, "w", encoding="utf-8") as f:
        json.dump(initial, f)
        
    patch = {
        "action": "CONFIG_INJECT",
        "target_file": test_target,
        "config_patch": {"noImplicitAny": False, "strictNullChecks": False}
    }
    success = Patcher.apply_patch(patch)
    assert success is True
    
    with open(test_target, "r", encoding="utf-8") as f:
        res = json.load(f)
        
    assert res["noImplicitAny"] is False
    assert res["compilerOptions"]["target"] == "ES2022"
    
    if os.path.exists(test_target):
        os.remove(test_target)

def test_file_create_and_delete():
    test_lock = "test_repo.lock"
    patch_create = {
        "action": "FILE_CREATE",
        "target_file": test_lock,
        "content": "LOCKED_PROCESS_ID=9999"
    }
    assert Patcher.apply_patch(patch_create) is True
    assert os.path.exists(test_lock)
    
    patch_delete = {
        "action": "FILE_DELETE",
        "target_file": test_lock
    }
    assert Patcher.apply_patch(patch_delete) is True
    assert not os.path.exists(test_lock)

if __name__ == "__main__":
    print("Running MCP Substitution tests...")
    test_mcp_substitution_config_file()
    print(" -> test_mcp_substitution_config_file: PASSED")
    test_mcp_substitution_dynamic_runtime()
    print(" -> test_mcp_substitution_dynamic_runtime: PASSED")
    test_config_inject()
    print(" -> test_config_inject: PASSED")
    test_file_create_and_delete()
    print(" -> test_file_create_and_delete: PASSED")
    print("ALL MCP SUBSTITUTION & PATTERNS TESTS PASSED 100%!")
