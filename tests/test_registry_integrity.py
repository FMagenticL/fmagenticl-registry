"""Deterministic v2.1.0 data hygiene, dual-signature, version parity, LocalCache, and dry-run Patcher gates."""

import base64
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fmagenticl import __version__
from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client.patchers import Patcher
from fmagenticl.client.verify import (
    canonical_json_bytes,
    compute_payload_hash,
    verify_patch_envelope,
    verify_patch_signature,
    verify_snapshot_file,
)
from fmagenticl.server.seed_hermes import RAW_SEED_CASES
from scripts.promote_d1_to_registry import scan_for_secrets

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"
BLOCKED_FILE_OPS = ("1a9650da", "7e212bac", "c3872804")


def test_patches_and_workarounds_zero_poison_zero_pii():
    patch_files = sorted((REPO_ROOT / "patches").glob("*.json"))
    assert len(patch_files) == 85

    non_json_re = re.compile(r"\.(?:py|js|ts|jsx|tsx|sh|bash|ps1|bat|md|txt)$", re.IGNORECASE)

    for pf in patch_files:
        data = json.loads(pf.read_text(encoding="utf-8"))
        raw_text = pf.read_text(encoding="utf-8")
        assert data.get("patch_type") != "code-remediation", f"Poisoned patch_type in {pf.name}"
        assert "slack.com/" not in raw_text.lower(), f"Slack link found in {pf.name}"
        has_secret, sec_label = scan_for_secrets(data)
        assert not has_secret, f"Secret {sec_label} found in {pf.name}"

        ops = data.get("json_patch") or []
        if ops:
            assert data.get("patch_type") == "application/json-patch+json", f"Unexpected json_patch on {pf.name}"
            tgt = data.get("target_file") or ""
            assert not non_json_re.search(tgt), f"Non-JSON target_file {tgt} in {pf.name}"
            for op in ops:
                path = op.get("path", "")
                val = op.get("value", "")
                assert not non_json_re.search(path), f"Non-JSON op path {path} in {pf.name}"
                if isinstance(val, str):
                    assert not val.startswith("Fix:") and "(Ref: http" not in val

    wrk_data = json.loads((REPO_ROOT / "dist" / "workarounds.json").read_text(encoding="utf-8"))
    for item in wrk_data.get("workarounds", []):
        serialized = json.dumps(item)
        assert "slack.com/" not in serialized.lower(), f"Slack URL leaked in workaround {item.get('id')}"


def test_resolve_and_snapshot_dual_signatures():
    resolve_files = sorted((REPO_ROOT / "dist" / "v1" / "resolve").glob("*.json"))
    assert len(resolve_files) == 129  # 85 canonical + 44 normalized aliases

    for rf in resolve_files:
        patch_obj = json.loads(rf.read_text(encoding="utf-8"))
        assert verify_patch_signature(patch_obj, require_signature=True), f"v1 sig failed: {rf.name}"
        assert verify_patch_envelope(
            patch_obj, expected_fingerprint=rf.stem, enforce_expiry=True
        ), f"v2 envelope failed: {rf.name}"

    dist_snap = REPO_ROOT / "dist" / "v1" / "snapshot.json"
    dist_sig = REPO_ROOT / "dist" / "v1" / "snapshot.sig"
    pkg_snap = REPO_ROOT / "fmagenticl" / "data" / "snapshot.json"
    pkg_sig = REPO_ROOT / "fmagenticl" / "data" / "snapshot.sig"

    assert pkg_snap.read_bytes() == dist_snap.read_bytes()
    assert pkg_sig.read_bytes() == dist_sig.read_bytes()
    assert verify_snapshot_file(str(pkg_snap), str(pkg_sig), require_signature=True)

    snap = json.loads(pkg_snap.read_text(encoding="utf-8"))
    assert len(snap["patches"]) == 85
    assert len(snap.get("aliases", {})) >= 44
    for fp_hex, patch_obj in snap["patches"].items():
        assert verify_patch_envelope(patch_obj, expected_fingerprint=fp_hex, enforce_expiry=True)


def test_health_census_and_version_parity_2_1_0():
    assert __version__ == "2.1.0"
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.1.0"' in pyproject

    health = json.loads((REPO_ROOT / "dist" / "v1" / "health").read_text(encoding="utf-8"))
    assert health["protocol_version"] == "2.1.0"
    assert health["compiled_patches"] == 85
    assert health["executable_patches"] == 54
    assert health["advisory_patches"] == 31
    assert health["executable_patches"] + health["advisory_patches"] == 85

    mcp_wellknown = json.loads((REPO_ROOT / "dist" / ".well-known" / "mcp.json").read_text(encoding="utf-8"))
    assert mcp_wellknown["serverInfo"]["version"] == "2.1.0"

    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    mw_uri = (REPO_ROOT / "functions" / "_middleware.js").as_uri()
    node_script = f"""
      const mcp = await import({json.dumps(mcp_uri)});
      const mw = await import({json.dumps(mw_uri)});
      const initRes = await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 1, method: 'initialize', params: {{}} }}),
        }}),
        env: {{ DB: null }},
      }});
      const initJson = await initRes.json();
      const cardRes = await mw.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp/server-card', {{ method: 'GET' }}),
        env: {{}},
        next: async () => new Response('miss', {{ status: 404 }}),
      }});
      const cardJson = await cardRes.json();
      process.stdout.write(JSON.stringify({{
        mcpInitVer: initJson.result.serverInfo.version,
        cardVer: cardJson.version,
      }}));
    """
    res = subprocess.run(
        [NODE, "--input-type=module", "-e", node_script],
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=30,
    )
    out = json.loads(res.stdout)
    assert out["mcpInitVer"] == "2.1.0"
    assert out["cardVer"] == "2.1.0"


def test_local_cache_offline_staleness_alias_and_breaker(tmp_path, monkeypatch):
    import httpx

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("Offline test must not call httpx.get")))

    # (a) Expired verified memory snapshot triggers staleness_warning=True without failing offline
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    fp = "a" * 64
    remediation = {"patch_type": "workaround_advisory", "workaround": "pin version"}
    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{fp}",
        "payload_hash": f"sha256:{compute_payload_hash(remediation)}",
        "valid_until": "2020-01-01T00:00:00Z",
        "min_client_version": "2.1.0",
    }
    expired_entry = {
        "fingerprint": f"sha256:{fp}",
        "remediation": remediation,
        "manifest": manifest,
        "signature": base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode(),
    }
    snap_path = tmp_path / "snap.json"
    sig_path = tmp_path / "snap.sig"
    snap_bytes = json.dumps(
        {"version": "2.1.0", "patches": {fp: expired_entry}, "aliases": {}},
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    snap_path.write_bytes(snap_bytes)
    sig_path.write_text(base64.b64encode(priv.sign(snap_bytes)).decode(), encoding="utf-8")

    mem_cache = LocalCache(
        snapshot_path=str(snap_path),
        sig_path=str(sig_path),
        delta_path=str(tmp_path / "delta_a.json"),
        public_key_b64=pub_b64,
    )
    stale_client = FMagenticLClient(local_cache=mem_cache, require_signature=True)
    stale_hit = stale_client.resolve(fp)
    assert stale_hit is not None
    assert stale_hit["signature_verified"] is True
    assert stale_hit["staleness_warning"] is True

    # (b) Bundled normalized alias resolves offline
    bundled_cache = LocalCache(delta_path=str(tmp_path / "delta_b.json"))
    client = FMagenticLClient(local_cache=bundled_cache, require_signature=True)
    snap_data = json.loads((REPO_ROOT / "fmagenticl" / "data" / "snapshot.json").read_text(encoding="utf-8"))
    norm_hex = next(iter(snap_data["aliases"].keys()))
    alias_hit = client.resolve(norm_hex)
    assert alias_hit is not None
    assert alias_hit["signature_verified"] is True
    assert alias_hit["fingerprint_verified"] is True

    # (c) Circuit breaker tripped OPEN still serves Tier-1 resolve_failure offline
    for _ in range(10):
        client.circuit_breaker.record_failure()
    assert not client.circuit_breaker.can_request()

    matched_case = None
    for c in RAW_SEED_CASES:
        cand = client.compute_fingerprint(c["env"], c["fail"]).replace("sha256:", "")
        if cand in snap_data["patches"]:
            matched_case = c
            break
    assert matched_case is not None
    breaker_hit = client.resolve_failure(matched_case["env"], matched_case["fail"])
    assert breaker_hit is not None
    assert breaker_hit["signature_verified"] is True


def test_patcher_dry_run_all_85_patches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Seed JSON fixture docs matching the 9 RFC 6902 application/json-patch+json patches
    fixtures = {
        "package.json": {"name": "demo", "engines": {"node": ">=18"}, "deprecated_schema": True},
        ".eslintrc.json": {"rules": {"invalid-rule": "error"}},
        "tsconfig.json": {"compilerOptions": {"noImplicitAny": True}},
        "hermes_config.json": {"mode": "local"},
        "mcp_config.json": {"servers": {}},
        "postcss.config.json": {"plugins": {"tailwindcss": {}}},
    }
    for name, body in fixtures.items():
        (tmp_path / name).write_text(json.dumps(body), encoding="utf-8")

    patch_files = sorted((REPO_ROOT / "patches").glob("*.json"))
    assert len(patch_files) == 85

    blocked_count = 0
    ok_count = 0
    for pf in patch_files:
        patch = json.loads(pf.read_text(encoding="utf-8"))
        ctx = {}
        res = Patcher.apply_patch(patch, context=ctx, dry_run=True)
        if pf.stem.startswith(BLOCKED_FILE_OPS):
            assert res is False, f"Security-blocked file-op unexpectedly returned True: {pf.name}"
            blocked_count += 1
        else:
            assert res is True, f"Valid patch failed dry_run validation: {pf.name} ({patch.get('patch_type')})"
            assert ctx.get("applied") is False
            ok_count += 1

    assert blocked_count == 3
    assert ok_count == 82


def test_source_patches_unsigned_and_compiled_surfaces_fully_enveloped():
    """F5 invariant: patches/*.json are unsigned source inputs; dist/ carries 100% dual-signed envelopes."""
    patch_files = sorted((REPO_ROOT / "patches").glob("*.json"))
    assert len(patch_files) == 85
    for pf in patch_files:
        data = json.loads(pf.read_text(encoding="utf-8"))
        assert "manifest" not in data, f"Source patch {pf.name} must not embed compiled manifest"
        assert "ed25519_sig" not in data, f"Source patch {pf.name} must not embed compiled signature"

    resolve_files = sorted((REPO_ROOT / "dist" / "v1" / "resolve").glob("*.json"))
    assert len(resolve_files) == 129
    for rf in resolve_files:
        obj = json.loads(rf.read_text(encoding="utf-8"))
        assert isinstance(obj.get("manifest"), dict), f"Compiled entry {rf.name} missing manifest"
        assert obj.get("ed25519_sig"), f"Compiled entry {rf.name} missing top-level ed25519_sig"
