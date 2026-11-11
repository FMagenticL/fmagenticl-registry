"""
Signature verification utilities for the FMagenticL client SDK.

Verifies Ed25519 cryptographic signatures on snapshot distributions, deltas,
and individual patch payloads to ensure authenticity and integrity before
ingestion into local cache memory.
"""

import base64
import json
import os
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Ed25519PublicKey = None
    InvalidSignature = Exception

from fmagenticl.client.config import FMAGENTICL_PUBLIC_KEY


def canonical_json_bytes(data: Any) -> bytes:
    """Deterministic UTF-8 JSON representation for cryptographic signing."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def compute_payload_hash(remediation: Any) -> str:
    """
    Computes a deterministic SHA-256 hex digest over canonical UTF-8 JSON
    representation of the actionable remediation payload.
    """
    if not isinstance(remediation, dict):
        remediation = {}
    payload_bytes = canonical_json_bytes(remediation)
    return hashlib.sha256(payload_bytes).hexdigest()


def verify_signature(
    payload_bytes: bytes,
    signature_b64: str,
    public_key_b64: Optional[str] = None,
) -> bool:
    """
    Verifies an Ed25519 signature over the provided payload bytes.

    Args:
        payload_bytes: Raw bytes of the payload (e.g. snapshot JSON).
        signature_b64: Base64-encoded Ed25519 signature string.
        public_key_b64: Base64-encoded raw 32-byte Ed25519 public key.
                        Defaults to FMAGENTICL_PUBLIC_KEY from config.

    Returns:
        True if the signature is authentic and valid; False otherwise.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return False

    key_str = public_key_b64 or FMAGENTICL_PUBLIC_KEY
    if not key_str or not signature_b64:
        return False

    try:
        pub_bytes = base64.b64decode(key_str.strip())
        sig_bytes = base64.b64decode(signature_b64.strip())
        if len(pub_bytes) != 32 or len(sig_bytes) != 64:
            return False

        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, payload_bytes)
        return True
    except (ValueError, InvalidSignature, Exception):
        return False


def verify_patch_signature(
    patch: Dict[str, Any],
    public_key_b64: Optional[str] = None,
    require_signature: bool = True,
) -> bool:
    """
    Verify the Ed25519 cryptographic authenticity of a resolved patch.

    STRICT INVARIANT:
    Returns True ONLY when an authentic Ed25519 signature ('signature' or 'ed25519_sig')
    is present on the patch and passes Ed25519PublicKey.verify() against the canonical
    JSON payload. Never returns True on unsigned payloads or shape-only checks.
    """
    if not isinstance(patch, dict):
        return False

    sig_b64 = patch.get("signature") or patch.get("ed25519_sig")
    if not sig_b64:
        return False

    clean_patch = {
        k: v
        for k, v in patch.items()
        if k not in ("signature", "ed25519_sig", "signature_verified", "fingerprint_verified")
    }
    payload_bytes = canonical_json_bytes(clean_patch)
    return verify_signature(payload_bytes, sig_b64, public_key_b64)


def verify_patch_envelope(
    patch: Dict[str, Any],
    expected_fingerprint: Optional[str] = None,
    public_key_b64: Optional[str] = None,
    require_signature: bool = True,
) -> bool:
    """
    Verifies a TUF-compliant signed manifest envelope on a patch payload.
    Cryptographically binds the target error query fingerprint to the
    executable remediation payload hash.

    Structure of manifest:
        {
            "manifest_version": 2,
            "target_fingerprint": "sha256:...",
            "payload_hash": "sha256:...",
            "valid_until": "2027-01-01T00:00:00Z",
            "min_client_version": "2.0.0"
        }
    """
    if not isinstance(patch, dict):
        return False

    manifest = patch.get("manifest")
    sig_b64 = patch.get("signature") or patch.get("ed25519_sig")
    if isinstance(manifest, dict) and not sig_b64:
        sig_b64 = manifest.get("signature") or manifest.get("ed25519_sig")

    if not manifest or not sig_b64:
        return not require_signature

    if not isinstance(manifest, dict):
        return False

    # 1. Target fingerprint check
    manifest_target_fp = str(manifest.get("target_fingerprint") or "").replace("sha256:", "").strip().lower()
    if not manifest_target_fp or len(manifest_target_fp) != 64 or not all(c in "0123456789abcdef" for c in manifest_target_fp):
        return False

    if expected_fingerprint:
        clean_expected = str(expected_fingerprint).replace("sha256:", "").strip().lower()
        if manifest_target_fp != clean_expected:
            return False

    patch_fp = patch.get("fingerprint")
    if patch_fp:
        clean_patch_fp = str(patch_fp).replace("sha256:", "").strip().lower()
        if clean_patch_fp != manifest_target_fp:
            return False

    # 2. Payload hash check
    remediation = patch.get("remediation")
    if remediation is None:
        remediation = patch.get("resolution_patch")
    if remediation is None:
        remediation = {
            k: v for k, v in patch.items()
            if k not in (
                "manifest", "signature", "ed25519_sig", "fingerprint",
                "signature_verified", "fingerprint_verified", "environment", "failure"
            )
        }

    computed_hash = compute_payload_hash(remediation)
    manifest_payload_hash = str(manifest.get("payload_hash") or "").replace("sha256:", "").strip().lower()

    if manifest_payload_hash != computed_hash:
        return False

    # 3. Validity timestamp check
    valid_until_str = manifest.get("valid_until")
    if valid_until_str:
        try:
            dt_str = str(valid_until_str).replace("Z", "+00:00")
            expiry = datetime.fromisoformat(dt_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expiry:
                return False
        except Exception:
            return False

    # 4. Ed25519 signature verification over canonical manifest bytes
    clean_manifest = {k: v for k, v in manifest.items() if k not in ("signature", "ed25519_sig")}
    manifest_bytes = canonical_json_bytes(clean_manifest)

    return verify_signature(manifest_bytes, sig_b64, public_key_b64=public_key_b64)


def verify_query_fingerprint(
    patch: Dict[str, Any],
    expected_fp: Optional[str] = None,
) -> bool:
    """
    Verify deterministic SHA-256 fingerprint integrity of a patch query.

    1. Validates that the fingerprint is a well-formed 64-character hex digest
       and matches expected_fp (when supplied).
    2. When 'environment' and 'failure' dicts are embedded in the patch,
       recomputes compute_fingerprint(environment, failure) and asserts
       exact cryptographic equality against the claimed fingerprint.
    3. Ensures the payload carries at least one recognized deterministic patch field.
    """
    if not isinstance(patch, dict):
        return False

    raw_fp = patch.get("fingerprint") or ""
    clean_fp = raw_fp.replace("sha256:", "").strip().lower()
    clean_expected = (expected_fp or "").replace("sha256:", "").strip().lower()

    if clean_expected:
        if clean_fp and clean_fp != clean_expected:
            return False
        target_fp = clean_expected
    else:
        target_fp = clean_fp

    if len(target_fp) != 64 or not all(c in "0123456789abcdef" for c in target_fp):
        return False

    env = patch.get("environment")
    fail = patch.get("failure")
    if isinstance(env, dict) and isinstance(fail, dict):
        from fmagenticl.client.fingerprint import compute_fingerprint
        recomputed = compute_fingerprint(env, fail).replace("sha256:", "").strip().lower()
        if recomputed != target_fp:
            return False

    patch_body = patch.get("resolution_patch") if isinstance(patch.get("resolution_patch"), dict) else (
        patch.get("remediation") if isinstance(patch.get("remediation"), dict) else patch
    )
    valid_fields = (
        "patch_type", "action", "json_patch", "fallback_cli", "file_ops",
        "mcp_uri", "strategy", "config_patch", "unified_diff", "dependency_pin",
        "workaround_advisory"
    )
    if not any(k in patch_body for k in valid_fields):
        return False

    return True


# Backward-compatible alias
verify_patch_fingerprint = verify_query_fingerprint


def verify_snapshot_file(
    snapshot_path: str,
    sig_path: Optional[str] = None,
    public_key_b64: Optional[str] = None,
    require_signature: bool = True,
) -> bool:
    """
    Verifies the signature of a snapshot file on disk.

    Args:
        snapshot_path: Path to the snapshot JSON file.
        sig_path: Path to the corresponding .sig file. If omitted,
                  probes {snapshot_path}.sig and {snapshot_stem}.sig.
        public_key_b64: Optional override public key.
        require_signature: If True, missing .sig file returns False with warning.

    Returns:
        True if signature exists and is valid; False otherwise.
    """
    if not os.path.isfile(snapshot_path):
        return False

    resolved_sig_path = sig_path
    if not resolved_sig_path:
        candidate_1 = snapshot_path.rsplit(".json", 1)[0] + ".sig" if snapshot_path.endswith(".json") else snapshot_path + ".sig"
        candidate_2 = snapshot_path + ".sig"
        if os.path.isfile(candidate_1):
            resolved_sig_path = candidate_1
        elif os.path.isfile(candidate_2):
            resolved_sig_path = candidate_2
        else:
            if require_signature:
                print(f"[FMagenticL Verify] Signature file missing for {snapshot_path} (require_signature=True)")
            return False

    if not os.path.isfile(resolved_sig_path):
        if require_signature:
            print(f"[FMagenticL Verify] Signature file missing for {snapshot_path} (require_signature=True)")
        return False

    try:
        with open(snapshot_path, "rb") as f_snap:
            payload_bytes = f_snap.read()
        with open(resolved_sig_path, "r", encoding="utf-8") as f_sig:
            sig_b64 = f_sig.read().strip()
        return verify_signature(payload_bytes, sig_b64, public_key_b64)
    except OSError as e:
        print(f"[FMagenticL Verify] Failed reading snapshot or signature: {e}")
        return False
