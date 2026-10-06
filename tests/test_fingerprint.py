"""
Fingerprint contract test.

This test asserts the exact hash value for a known input. If the
fingerprint algorithm changes — normalization rules, separator order,
field ordering, casing, truncation — this test fails immediately.

Prefix and length checks are insufficient. Those pass even when the
algorithm produces a different hash, which means the client silently
loses the ability to resolve any patch in the registry.

Reference values are pinned to the fingerprints that generated
patches/*.json and fmagenticl.db. Do not update them without also
re-seeding the registry.
"""

from fmagenticl.client.fingerprint import compute_fingerprint


# --- Reference case pinned from RAW_SEED_CASES[0] ---

REFERENCE_ENV = {
    "os": "win32",
    "os_version": "10.0.26100",
    "runtime": "node@24.15.0",
    "package": "hermes-agent@0.4.8",
}

REFERENCE_FAILURE = {
    "error_code": "EBADENGINE",
    "exit_code": 1,
    "raw_signature": "npm ERR! code EBADENGINE",
}

REFERENCE_HASH = (
    "sha256:49f800ca559979a58e778451778b318026853c0c37814f1880b64047db68fae6"
)


def test_fingerprint_generation():
    """Shape checks. Cheap sanity test, kept for fast feedback."""
    fp = compute_fingerprint(REFERENCE_ENV, REFERENCE_FAILURE)
    assert fp.startswith("sha256:")
    assert len(fp) == 71


def test_fingerprint_exact_hash():
    """
    Exact hash assertion. This is the load-bearing test.

    If this fails, the fingerprint algorithm has changed. Every
    registered patch in the registry is now unreachable by the client.
    Do not update this value to make the test pass — revert the
    algorithm change instead.
    """
    fp = compute_fingerprint(REFERENCE_ENV, REFERENCE_FAILURE)
    assert fp == REFERENCE_HASH, (
        f"Fingerprint algorithm has changed.\n"
        f"  Expected: {REFERENCE_HASH}\n"
        f"  Got:      {fp}\n"
        f"Revert the algorithm change. Do not update this test."
    )


def test_fingerprint_determinism():
    """Same input always produces the same output."""
    for _ in range(10):
        fp = compute_fingerprint(REFERENCE_ENV, REFERENCE_FAILURE)
        assert fp == REFERENCE_HASH
