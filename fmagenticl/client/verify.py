"""
Signature verification utilities for the FMagenticL client SDK.

Verifies Ed25519 cryptographic signatures on snapshot distributions and deltas
to ensure authenticity and integrity before ingestion into local cache memory.
"""

import base64
import os
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Ed25519PublicKey = None
    InvalidSignature = Exception

from fmagenticl.client.config import FMAGENTICL_PUBLIC_KEY


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


def verify_snapshot_file(
    snapshot_path: str,
    sig_path: Optional[str] = None,
    public_key_b64: Optional[str] = None,
) -> bool:
    """
    Verifies the signature of a snapshot file on disk.

    Args:
        snapshot_path: Path to the snapshot JSON file.
        sig_path: Path to the corresponding .sig file. If omitted,
                  probes {snapshot_path}.sig and {snapshot_stem}.sig.
        public_key_b64: Optional override public key.

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
            return False

    if not os.path.isfile(resolved_sig_path):
        return False

    try:
        with open(snapshot_path, "rb") as f_snap:
            payload_bytes = f_snap.read()
        with open(resolved_sig_path, "r", encoding="utf-8") as f_sig:
            sig_b64 = f_sig.read().strip()
        return verify_signature(payload_bytes, sig_b64, public_key_b64)
    except OSError:
        return False
