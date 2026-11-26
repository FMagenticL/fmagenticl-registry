"""Cross-language Python <-> Node.js JCS + Ed25519 parity, revoked kid hard-fail, and rollback tests."""

import base64
import copy
import datetime
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fmagenticl.client.jcs import jcs_bytes
from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.verify import V3_SIG_DOMAIN, resolve_public_key_for_kid, verify_patch_envelope

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"


def _signed_v3_record(priv: Ed25519PrivateKey, kid: str = "test-kid-1", seq: int = 3001, days: int = 14):
    rec = json.loads((REPO_ROOT / "signatures" / "SIG-2026-0001.json").read_text(encoding="utf-8"))
    body_hash = "sha256:" + hashlib.sha256(jcs_bytes(rec)).hexdigest()
    now = datetime.datetime.now(datetime.timezone.utc)
    manifest_unsigned = {
        "manifest_version": 3,
        "kid": kid,
        "snapshot_seq": seq,
        "target_id": rec["id"],
        "target_fingerprint": rec["fingerprint"],
        "payload_hash": body_hash,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_until": (now + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    sig_b64 = base64.b64encode(priv.sign(V3_SIG_DOMAIN + jcs_bytes(manifest_unsigned))).decode("ascii")
    rec["manifest"] = {**manifest_unsigned, "ed25519_sig": sig_b64}
    return rec


def test_python_node_jcs_and_ed25519_parity(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    rec = _signed_v3_record(priv)

    assert verify_patch_envelope(rec, public_key_b64=pub_b64) is True

    tampered = copy.deepcopy(rec)
    tampered["title"] = "Tampered Title"
    assert verify_patch_envelope(tampered, public_key_b64=pub_b64) is False

    expired = _signed_v3_record(priv, days=-1)
    assert verify_patch_envelope(expired, public_key_b64=pub_b64, enforce_expiry=True) is False

    keyring = {
        "keys": {
            "active-kid": {"public_key_b64": pub_b64, "status": "active"},
            "revoked-kid": {"public_key_b64": pub_b64, "status": "revoked"},
        }
    }
    assert resolve_public_key_for_kid("active-kid", keyring=keyring["keys"]) == pub_b64
    assert resolve_public_key_for_kid("revoked-kid", keyring=keyring["keys"], allow_retired=True) is None
    assert resolve_public_key_for_kid("unknown-kid", keyring=keyring["keys"]) is None

    js_sdk = str(REPO_ROOT / "packages" / "client" / "index.js").replace("\\", "/")
    node_script = f"""
      const Client = require({json.dumps(js_sdk)});
      const rec = {json.dumps(rec)};
      const tampered = {json.dumps(tampered)};
      const expired = {json.dumps(expired)};
      const keyring = {json.dumps(keyring)};
      const revokedRec = JSON.parse(JSON.stringify(rec));
      revokedRec.manifest.kid = 'revoked-kid';
      const activeRec = JSON.parse(JSON.stringify(rec));
      // Check active, tampered, expired, revoked, and rollback
      process.stdout.write(JSON.stringify({{
        valid: Client.verifySignatureRecord(rec, {{ publicKeyB64: {json.dumps(pub_b64)} }}),
        tampered: Client.verifySignatureRecord(tampered, {{ publicKeyB64: {json.dumps(pub_b64)} }}),
        expired: Client.verifySignatureRecord(expired, {{ publicKeyB64: {json.dumps(pub_b64)} }}),
        revoked: Client.verifySignatureRecord(revokedRec, {{ keyring }}),
        rollback: Client.verifySignatureRecord(rec, {{ publicKeyB64: {json.dumps(pub_b64)}, minSnapshotSeq: 3005 }}),
      }}));
    """
    proc = subprocess.run([NODE, "-e", node_script], capture_output=True, text=True, check=True)
    res = json.loads(proc.stdout)
    assert res == {"valid": True, "tampered": False, "expired": False, "revoked": False, "rollback": False}


def test_local_cache_rejects_snapshot_seq_rollback(tmp_path):
    snap = tmp_path / "snapshot.json"
    snap.write_text(json.dumps({"snapshot_seq": 3010, "patches": {}, "aliases": {}}), encoding="utf-8")
    cache = LocalCache(snapshot_path=str(snap), delta_path=str(tmp_path / "delta.json"), verify_signature=False)
    try:
        cache.put("a" * 64, {"manifest": {"snapshot_seq": 3005}})
        raised = False
    except ValueError:
        raised = True
    assert raised is True
