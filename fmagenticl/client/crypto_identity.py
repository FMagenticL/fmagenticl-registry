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
    def compute_pow(public_key_b64: str, difficulty_bits: int) -> str:
        """
        Find a nonce such that SHA256(public_key + nonce) starts with `difficulty_bits` zero bits.
        Returns nonce as hex string.
        """
        target_prefix = '0' * difficulty_bits
        nonce_int = 0
        while True:
            nonce = nonce_int.to_bytes(16, 'big').hex()
            data = f"{public_key_b64}:{nonce}".encode()
            h = hashlib.sha256(data).hexdigest()
            if h.startswith(target_prefix):
                return nonce
            nonce_int += 1

    @staticmethod
    def verify_pow(public_key_b64: str, nonce: str, difficulty_bits: int) -> bool:
        """Verify a proof-of-work solution."""
        data = f"{public_key_b64}:{nonce}".encode()
        h = hashlib.sha256(data).hexdigest()
        return h.startswith('0' * difficulty_bits)
