import os
import json
import stat
from fmagenticl.client.patchers import Patcher


def test_rfc6902_json_patch_success():
    test_json = "test_rfc6902_pkg.json"
    data = {
        "name": "test-app",
        "version": "1.0.0",
        "engines": {"node": ">=22", "npm": ">=10"},
        "scripts": {"build": "vite build"},
    }
    with open(test_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    patch = {
        "patch_type": "application/json-patch+json",
        "target_file": test_json,
        "json_patch": [
            {"op": "test", "path": "/name", "value": "test-app"},
            {"op": "remove", "path": "/engines"},
            {"op": "add", "path": "/type", "value": "module"},
        ],
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


def test_dry_run_never_mutates_disk_or_executes_cli(monkeypatch):
    """
    Regression test for v1.4.0 Catch #1:
    dry_run=True (and _auto_heal) MUST leave target files 100% untouched on disk
    across RFC 6902 json_patch, FILE_CREATE, CONFIG_INJECT, AST_DELETE_KEY, and CLI_OVERRIDE.
    """
    test_json = "test_dryrun_immutability.json"
    original = {"name": "immutable-pkg", "version": "1.0.0", "drop_me": True}
    with open(test_json, "w", encoding="utf-8") as f:
        raw_before = json.dumps(original, indent=2)
        f.write(raw_before)

    try:
        # 1. RFC 6902 dry-run
        ctx_json = {"dry_run": True}
        ok = Patcher.apply_patch(
            {
                "patch_type": "application/json-patch+json",
                "target_file": test_json,
                "json_patch": [{"op": "replace", "path": "/version", "value": "9.9.9"}],
            },
            ctx_json,
        )
        assert ok is True
        assert ctx_json["applied"] is False
        assert ctx_json["preview_patched_doc"]["version"] == "9.9.9"
        with open(test_json, "r", encoding="utf-8") as f:
            assert f.read() == raw_before

        # 2. FILE_CREATE dry-run
        ghost_file = "test_ghost_should_not_exist.txt"
        if os.path.exists(ghost_file):
            os.remove(ghost_file)
        ctx_create = {}
        ok_create = Patcher.apply_patch(
            {"action": "FILE_CREATE", "target_file": ghost_file, "content": "boom"},
            ctx_create,
            dry_run=True,
        )
        assert ok_create is True
        assert ctx_create["applied"] is False
        assert not os.path.exists(ghost_file)

        # 3. CLI_OVERRIDE with caller attempting apply_cli=True while dry_run=True
        ctx_cli = {"apply_cli": True, "dry_run": True}
        ok_cli = Patcher.apply_patch(
            {"patch_type": "cli-override", "fallback_cli": "pip --version"},
            ctx_cli,
        )
        assert ok_cli is True
        assert ctx_cli["applied"] is False
        assert ctx_cli["advisory_cli"] == "pip --version"

        # 4. MCP _auto_heal end-to-end cannot be tricked by context={"apply_cli": True, "dry_run": False}
        import fmagenticl.client.fastmcp_server as fmcp

        class _StubClient:
            def resolve_failure(self, env, fail, context=None):
                return {
                    "fingerprint": "sha256:" + ("c" * 64),
                    "signature_verified": False,
                    "fingerprint_verified": True,
                    "resolution_patch": {
                        "patch_type": "application/json-patch+json",
                        "target_file": test_json,
                        "json_patch": [{"op": "replace", "path": "/version", "value": "HACKED"}],
                    },
                }

        monkeypatch.setattr(fmcp, "_get_client", lambda: _StubClient())
        heal_out = fmcp._auto_heal({}, {}, context={"apply_cli": True, "dry_run": False})
        assert heal_out["status"] == "VALIDATED_DRY_RUN"
        assert heal_out["applied"] is False
        assert heal_out["signature_verified"] is False
        with open(test_json, "r", encoding="utf-8") as f:
            assert f.read() == raw_before
    finally:
        if os.path.exists(test_json):
            os.remove(test_json)


def test_rfc6902_test_op_atomic_rollback():
    test_json = "test_atomic_rollback.json"
    data = {"name": "critical-service", "version": "2.0.0", "safe_key": "untouched"}
    with open(test_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    patch = {
        "patch_type": "application/json-patch+json",
        "target_file": test_json,
        "json_patch": [
            {"op": "test", "path": "/version", "value": "1.0.0"},
            {"op": "replace", "path": "/safe_key", "value": "CORRUPTED"},
        ],
    }

    res = Patcher.apply_patch(patch, {})
    assert res is False

    with open(test_json, "r", encoding="utf-8") as f:
        curr_data = json.load(f)

    assert curr_data["safe_key"] == "untouched"
    assert curr_data["version"] == "2.0.0"

    if os.path.exists(test_json):
        os.remove(test_json)


def test_ast_delete_key_legacy_patcher():
    test_json = "test_package.json"
    data = {"name": "test-app", "version": "1.0.0", "engines": {"node": ">=22", "npm": ">=10"}}
    with open(test_json, "w", encoding="utf-8") as f:
        json.dump(data, f)

    patch = {"action": "AST_DELETE_KEY", "target_file": test_json, "key_path": "engines"}
    res = Patcher.apply_patch(patch, {})
    assert res is True

    with open(test_json, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    assert "engines" not in new_data
    assert new_data["name"] == "test-app"

    if os.path.exists(test_json):
        os.remove(test_json)


def test_file_permission_unlock():
    test_file = "locked_file.txt"
    if os.path.exists(test_file):
        os.chmod(test_file, stat.S_IWRITE)
        os.remove(test_file)
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("locked")

    os.chmod(test_file, stat.S_IREAD)
    patch = {"action": "FILE_PERMISSION_UNLOCK", "target_file": test_file}
    res = Patcher.apply_patch(patch, {})
    assert res is False

    os.chmod(test_file, stat.S_IWRITE)
    os.remove(test_file)


def test_peripheral_file_op():
    test_file = "created_by_op.txt"
    if os.path.exists(test_file):
        os.remove(test_file)

    patch = {
        "patch_type": "file-op",
        "file_ops": [{"op": "create", "target_file": test_file, "content": "auto-generated header\n"}],
    }
    res = Patcher.apply_patch(patch, {})
    assert res is True
    assert os.path.exists(test_file)
    with open(test_file, "r", encoding="utf-8") as f:
        assert f.read() == "auto-generated header\n"
    os.remove(test_file)
