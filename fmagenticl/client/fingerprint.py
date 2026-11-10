"""
FMagenticL - Client fingerprint hashing and error signature normalization utility.
"""
import hashlib
import re

_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{6,16}")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_USER_PATH_RE = re.compile(r"(?:/Users/[^/\s\"']+|/home/[^/\s\"']+|[A-Za-z]:\\Users\\[^\\\s\"']+)")
_LINE_NUM_RE = re.compile(r"(\bline\s+)\d+\b", re.IGNORECASE)


def normalize_error_signature(raw_str: str) -> str:
    """
    Strip volatile runtime tokens (memory addresses, UUIDs, ISO timestamps,
    OS user home paths, and line numbers) before hashing so identical failure
    modes produce identical fingerprints across machines.
    """
    if not raw_str or not isinstance(raw_str, str):
        return ""
    s = _HEX_ADDR_RE.sub("0xADDR", raw_str)
    s = _UUID_RE.sub("<UUID>", s)
    s = _ISO_TS_RE.sub("<TIMESTAMP>", s)
    s = _USER_PATH_RE.sub("<USER_HOME>", s)
    s = _LINE_NUM_RE.sub(r"\1<LINE>", s)
    return s


def compute_fingerprint(environment: dict, failure: dict) -> str:
    """Type-safe deterministic SHA-256 fingerprint hashing using canonical sorted keys."""
    env_str = "|".join(f"{k}:{v}" for k, v in sorted(environment.items()) if v is not None)
    norm_fail = {}
    for k, v in sorted(failure.items()):
        if v is not None:
            norm_fail[k] = normalize_error_signature(v) if isinstance(v, str) else v
    fail_str = "|".join(f"{k}:{v}" for k, v in norm_fail.items())
    raw = f"{env_str}||{fail_str}"
    return "sha256:" + hashlib.sha256(raw.encode('utf-8')).hexdigest()
