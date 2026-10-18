from fmagenticl.normalizer import normalize_error_string, canonical_fingerprint

TEST_VECTOR = (
    "RuntimeError at 0x7ffee3b4c000 in /Users/alice/app/main.py:142:18 "
    "(lib v2.4.19) at 2026-10-14T10:42:00Z"
)
EXPECTED_CANONICAL = (
    "RuntimeError at <HEX_ADDR> in <USER_HOME>/app/main.py:<LINE>:<COL> "
    "(lib v2.4.x) at <TIMESTAMP>"
)
EXPECTED_HASH = "4fa7f8a7abab80e236000d115ea851a9c15c4473adca82af7743d99a1f6676e1"


def test_canonical_output():
    assert normalize_error_string(TEST_VECTOR) == EXPECTED_CANONICAL


def test_canonical_hash_is_deterministic_and_pinned():
    h1 = canonical_fingerprint(TEST_VECTOR)
    h2 = canonical_fingerprint(TEST_VECTOR)
    assert h1 == h2
    assert len(h1) == 64
    assert h1 == EXPECTED_HASH


def test_no_time_of_day_corruption():
    sample = "[10:42:00] server started"
    normalized = normalize_error_string(sample)
    assert "<LINE>:<COL>" not in normalized
    assert "10:42:00" in normalized
