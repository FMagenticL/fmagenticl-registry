"""
Tests for Ed25519 signature verification on static distributions and local cache.
"""

import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fmagenticl.client.verify import verify_signature, verify_snapshot_file
from fmagenticl.client.local_cache import LocalCache


def _generate_test_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_bytes).decode()
    return priv, pub_b64


def test_valid_signature_verification():
    """Valid Ed25519 signature on payload passes verification."""
    priv, pub_b64 = _generate_test_keypair()
    payload = b'{"version":"1.3.1","patches":{"abc":{"type":"test"}}}'
    sig = base64.b64encode(priv.sign(payload)).decode()

    assert verify_signature(payload, sig, public_key_b64=pub_b64) is True


def test_tampered_payload_fails_verification():
    """Tampering with signed payload bytes causes verification to fail."""
    priv, pub_b64 = _generate_test_keypair()
    payload = b'{"version":"1.3.1","patches":{"abc":{"type":"test"}}}'
    sig = base64.b64encode(priv.sign(payload)).decode()

    tampered = b'{"version":"1.3.1","patches":{"abc":{"type":"hacked"}}}'
    assert verify_signature(tampered, sig, public_key_b64=pub_b64) is False


def test_invalid_signature_format_or_key_fails():
    """Malformed signatures or invalid keys return False cleanly without crashing."""
    _, pub_b64 = _generate_test_keypair()
    payload = b'{"hello":"world"}'

    # Invalid base64
    assert verify_signature(payload, "not-valid-base64!!!", public_key_b64=pub_b64) is False
    # Short signature
    assert verify_signature(payload, base64.b64encode(b"short").decode(), public_key_b64=pub_b64) is False
    # Empty inputs
    assert verify_signature(payload, "", public_key_b64=pub_b64) is False
    assert verify_signature(b"", "", public_key_b64="") is False


def test_local_cache_signature_enforcement(tmp_path):
    """LocalCache loads signed snapshots and refuses tampered snapshots."""
    priv, pub_b64 = _generate_test_keypair()

    snap_file = tmp_path / "test_snapshot.json"
    sig_file = tmp_path / "test_snapshot.sig"

    snap_data = {
        "version": "1.3.1",
        "patches": {
            "test_fp": {"patch_type": "cli-override", "cmd": "echo ok"}
        }
    }
    payload_bytes = json.dumps(snap_data, separators=(",", ":"), sort_keys=True).encode()
    sig_b64 = base64.b64encode(priv.sign(payload_bytes)).decode()

    snap_file.write_bytes(payload_bytes)
    sig_file.write_text(sig_b64)

    # 1. Valid snapshot and signature -> loaded into memory
    cache_valid = LocalCache(
        snapshot_path=str(snap_file),
        sig_path=str(sig_file),
        public_key_b64=pub_b64,
        verify_signature=True,
    )
    assert "test_fp" in cache_valid._memory
    assert cache_valid.get("test_fp")["cmd"] == "echo ok"

    # 2. Tampered snapshot -> rejected, memory remains empty
    snap_file.write_bytes(b'{"version":"1.3.1","patches":{"tampered":true}}')
    cache_tampered = LocalCache(
        snapshot_path=str(snap_file),
        sig_path=str(sig_file),
        public_key_b64=pub_b64,
        verify_signature=True,
    )
    assert len(cache_tampered._memory) == 0
    assert cache_tampered.get("tampered") is None
