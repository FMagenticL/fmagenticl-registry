"""
Tests for Ed25519 signature verification and SHA-256 fingerprint integrity
on static distributions, individual resolved patches, and local cache.
"""

import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fmagenticl.client.fingerprint import compute_fingerprint
from fmagenticl.client.verify import (
    canonical_json_bytes,
    verify_patch_fingerprint,
    verify_patch_signature,
    verify_signature,
    verify_snapshot_file,
)
from fmagenticl.client.local_cache import LocalCache


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
