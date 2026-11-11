"""
FMagenticL - Ed25519 identity management and anti-sybil proof-of-work.
"""
import base64
import hashlib
import json
import os
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


class AgentIdentity:
    """
    Manages Ed25519 keypair for an agent, provides signing and PoW utilities.
    """
    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        if private_key is None:
            self.private_key = Ed25519PrivateKey.generate()
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_private_key_pem(cls, pem_bytes: bytes) -> 'AgentIdentity':
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        return cls(private_key)

    def public_key_bytes(self) -> bytes:
        """Return raw public key bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def public_key_b64(self) -> str:
        """Return base64-encoded public key."""
        return base64.b64encode(self.public_key_bytes()).decode()

    def sign(self, data: bytes) -> bytes:
        """Sign data and return signature bytes."""
        return self.private_key.sign(data)

    def sign_b64(self, data: bytes) -> str:
        return base64.b64encode(self.sign(data)).decode()

    @staticmethod
    def verify(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64)
            )
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, data)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_pow(public_key_b64: str, nonce: str, difficulty_bits: int) -> bool:
        """
        Verify a proof-of-work solution by checking leading zero bits.
        """
        if difficulty_bits <= 0:
            return True
        if not nonce or not isinstance(nonce, str):
            return False
        data = f"{public_key_b64}:{nonce}".encode("utf-8")
        h_bytes = hashlib.sha256(data).digest()
        full_bytes = difficulty_bits // 8
        if h_bytes[:full_bytes] != b"\x00" * full_bytes:
            return False
        rem = difficulty_bits % 8
        if rem > 0:
            return (h_bytes[full_bytes] >> (8 - rem)) == 0
        return True

    @staticmethod
    def compute_pow(
        public_key_b64: str,
        difficulty_bits: int,
        max_iterations: int = 500_000
    ) -> Optional[str]:
        """
        Find a nonce such that SHA256(public_key:nonce) starts with `difficulty_bits` zero bits.
        Returns nonce as hex string, or None if target is not reached within max_iterations.
        """
        if difficulty_bits <= 0:
            return "0" * 32

        full_bytes = difficulty_bits // 8
        rem = difficulty_bits % 8
        prefix = f"{public_key_b64}:".encode("utf-8")
        prefix_zero_bytes = b"\x00" * full_bytes
        base_hasher = hashlib.sha256(prefix)

        for nonce_int in range(max_iterations):
            nonce = f"{nonce_int:032x}"
            hasher = base_hasher.copy()
            hasher.update(nonce.encode("ascii"))
            h_bytes = hasher.digest()
            if h_bytes[:full_bytes] == prefix_zero_bytes:
                if rem == 0 or (h_bytes[full_bytes] >> (8 - rem)) == 0:
                    return nonce
        return None
