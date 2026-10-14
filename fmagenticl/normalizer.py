"""Canonical error normalizer — parity with functions/mcp.js normalizeErrorString."""
import hashlib
import re

_HEX_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{6,16}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_USER_HOME_RE = re.compile(r"(?:/Users/|/home/|C:\\Users\\)[^/\s\\]+")
_LINE_COL_RE = re.compile(r"(?<!\d):(\d+):(\d+)\b")
_SEMVER_RE = re.compile(r"\bv?(\d+)\.(\d+)\.(\d+)\b")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_error_string(raw: str) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    s = raw.strip()
    s = _HEX_ADDR_RE.sub("<HEX_ADDR>", s)
    s = _UUID_RE.sub("<UUID>", s)
    s = _TIMESTAMP_RE.sub("<TIMESTAMP>", s)
    s = _USER_HOME_RE.sub("<USER_HOME>", s)
    s = _LINE_COL_RE.sub(":<LINE>:<COL>", s)
    s = _SEMVER_RE.sub(r"v\1.\2.x", s)
    s = _WHITESPACE_RE.sub(" ", s)
    return s


def canonical_fingerprint(raw: str) -> str:
    return hashlib.sha256(normalize_error_string(raw).encode("utf-8")).hexdigest()
