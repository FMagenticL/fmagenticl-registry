"""
FMagenticL - Client fingerprint hashing utility.
"""
import hashlib

def compute_fingerprint(environment: dict, failure: dict) -> str:
    """Type-safe deterministic SHA-256 fingerprint hashing using canonical sorted keys."""
    env_str = "|".join(f"{k}:{v}" for k, v in sorted(environment.items()) if v is not None)
    fail_str = "|".join(f"{k}:{v}" for k, v in sorted(failure.items()) if v is not None)
    raw = f"{env_str}||{fail_str}"
    return "sha256:" + hashlib.sha256(raw.encode('utf-8')).hexdigest()
