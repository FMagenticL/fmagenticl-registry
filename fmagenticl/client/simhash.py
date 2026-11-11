"""
FMagenticL - 64-Bit FNV-1a SimHash and Locality-Sensitive Hashing (LSH) Engine.

Computes 64-bit SimHash fingerprints over normalized error signatures to enable
fuzzy deduplication and near-neighbor lookup across minor runtime variations.
"""

import re
from typing import Tuple, List

# Pinned 64-bit FNV-1a Constants
FNV_OFFSET_BASIS: int = 0xcbf29ce484222325
FNV_PRIME: int = 0x100000001b3
MASK64: int = 0xFFFFFFFFFFFFFFFF

# Standard Traceback Boilerplate Tokens (stripped to avoid biasing hash)
BOILERPLATE_TOKENS = {
    "traceback", "most", "recent", "call", "last",
    "file", "line", "in", "raise"
}

_EXC_RE = re.compile(r"\b[A-Z][a-zA-Z0-9]*(?:Error|Exception|Fault|Warning)\b")
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_]{2,}\b")


def fnv1a_64(text: str) -> int:
    """Type-safe 64-bit FNV-1a hash over UTF-8 bytes."""
    h = FNV_OFFSET_BASIS
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * FNV_PRIME) & MASK64
    return h


def popcount64(x: int) -> int:
    """Count set bits in a 64-bit integer (Python 3.8+ compatible)."""
    return bin(x & MASK64).count("1")


def hamming_distance(h1: int, h2: int) -> int:
    """Compute bitwise Hamming distance between two 64-bit hashes."""
    return popcount64(h1 ^ h2)


def tokenize_error(text: str) -> List[Tuple[str, int]]:
    """
    Extract meaningful identifier tokens from error text.
    Exception classes receive weight 3; standard identifiers receive weight 1.
    Traceback boilerplate tokens are pruned.
    """
    if not text or not isinstance(text, str):
        return []
    
    tokens: List[Tuple[str, int]] = []
    raw_tokens = _TOKEN_RE.findall(text)
    
    for tok in raw_tokens:
        tok_lower = tok.lower()
        if tok_lower in BOILERPLATE_TOKENS:
            continue
        weight = 3 if _EXC_RE.match(tok) else 1
        tokens.append((tok, weight))
    
    return tokens


def compute_simhash(text: str) -> int:
    """
    Compute 64-bit SimHash vector over extracted and weighted tokens.
    Returns unsigned 64-bit integer.
    """
    tokens = tokenize_error(text)
    if not tokens:
        return 0

    v = [0] * 64
    for tok, weight in tokens:
        h = fnv1a_64(tok)
        for i in range(64):
            if (h >> i) & 1:
                v[i] += weight
            else:
                v[i] -= weight

    sim = 0
    for i in range(64):
        if v[i] > 0:
            sim |= (1 << i)
    return sim


def split_simhash_bands(sim: int) -> Tuple[int, int, int, int]:
    """
    Partition 64-bit SimHash into four 16-bit unsigned integer bands for LSH indexing:
        b0: bits 63..48
        b1: bits 47..32
        b2: bits 31..16
        b3: bits 15..0
    """
    b0 = (sim >> 48) & 0xFFFF
    b1 = (sim >> 32) & 0xFFFF
    b2 = (sim >> 16) & 0xFFFF
    b3 = sim & 0xFFFF
    return b0, b1, b2, b3
