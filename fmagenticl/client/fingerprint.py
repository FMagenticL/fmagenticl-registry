"""
FMagenticL - Client fingerprint hashing and error signature normalization utility.
"""
import hashlib
import re

_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{6,16}")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_USER_PATH_RE = re.compile(r"(?:/Users/[^/\s\"']+|/home/[^/\s\"']+|/root/[^/\s\"']+|[A-Za-z]:[/\\]Users\\[^\\\s\"']+)")
_LINE_NUM_RE = re.compile(r"(\bline\s+)\d+\b", re.IGNORECASE)
_RUNTIME_PATCH_RE = re.compile(r"\b([a-zA-Z0-9_-]+@\d+\.\d+)\.\d+\b")


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


def compute_fingerprint(environment: dict, failure: dict, normalize: bool = False) -> str:
    """Type-safe deterministic SHA-256 fingerprint hashing using canonical sorted keys."""
    env_dict = environment
    fail_dict = failure
    if normalize:
        env_dict = {}
        for k, v in sorted(environment.items()):
            if v is not None:
                if k == "runtime" and isinstance(v, str):
                    env_dict[k] = _RUNTIME_PATCH_RE.sub(r"\1", v)
                else:
                    env_dict[k] = normalize_error_signature(v) if isinstance(v, str) else v

        fail_dict = {}
        for k, v in sorted(failure.items()):
            if v is not None:
                fail_dict[k] = normalize_error_signature(v) if isinstance(v, str) else v

    env_str = "|".join(f"{k}:{v}" for k, v in sorted(env_dict.items()) if v is not None)
    fail_str = "|".join(f"{k}:{v}" for k, v in sorted(fail_dict.items()) if v is not None)
    raw = f"{env_str}||{fail_str}"
    return "sha256:" + hashlib.sha256(raw.encode('utf-8')).hexdigest()


def compute_normalized_fingerprint(environment: dict, failure: dict) -> str:
    """Alias for compute_fingerprint with normalize=True."""
    return compute_fingerprint(environment, failure, normalize=True)
