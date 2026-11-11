"""
Contract tests for 64-Bit FNV-1a SimHash and LSH Band Splitting.
"""

from fmagenticl.client.simhash import (
    fnv1a_64,
    compute_simhash,
    split_simhash_bands,
    popcount64,
    hamming_distance,
    FNV_OFFSET_BASIS,
    FNV_PRIME,
    MASK64,
)


def test_fnv1a_constants_and_determinism():
    """Verify pinned 64-bit FNV-1a constants and empty string hash."""
    assert FNV_OFFSET_BASIS == 0xcbf29ce484222325
    assert FNV_PRIME == 0x100000001b3
    assert MASK64 == 0xFFFFFFFFFFFFFFFF
    
    # Empty string should hash strictly to FNV offset basis
    assert fnv1a_64("") == FNV_OFFSET_BASIS

    # Determinism across multiple executions
    h1 = fnv1a_64("FileNotFoundError")
    h2 = fnv1a_64("FileNotFoundError")
    assert h1 == h2
    assert isinstance(h1, int)
    assert 0 <= h1 <= MASK64


def test_popcount64():
    """Verify bit counting helper."""
    assert popcount64(0) == 0
    assert popcount64(1) == 1
    assert popcount64(0b10110) == 3
    assert popcount64(MASK64) == 64
    assert popcount64(0xFFFF) == 16


def test_identical_errors_hamming_distance_zero():
    """Identical errors must produce identical SimHash (Hamming distance == 0)."""
    err = (
        "Traceback (most recent call last):\n"
        "  File \"app.py\", line 42, in <module>\n"
        "    FileNotFoundError: [Errno 2] No such file or directory: 'config.json'"
    )
    sim1 = compute_simhash(err)
    sim2 = compute_simhash(err)
    assert sim1 == sim2
    assert hamming_distance(sim1, sim2) == 0


def test_minor_variations_maintain_low_hamming_distance():
    """
    Minor variations in line number, path, or variable names maintain Hamming distance <= 3.
    """
    base_err = (
        "Traceback (most recent call last):\n"
        "  File \"src/worker.py\", line 105, in run_task\n"
        "    ConnectionRefusedError: [Errno 111] Connection refused connecting to redis://localhost:6379"
    )
    var_err = (
        "Traceback (most recent call last):\n"
        "  File \"src/worker.py\", line 109, in run_task\n"
        "    ConnectionRefusedError: [Errno 111] Connection refused connecting to redis://127.0.0.1:6379"
    )
    sim_base = compute_simhash(base_err)
    sim_var = compute_simhash(var_err)
    dist = hamming_distance(sim_base, sim_var)
    assert dist <= 3, f"Expected Hamming distance <= 3, got {dist}"


def test_distinct_errors_exceed_distance_threshold():
    """
    Completely different errors and exceptions must exceed the similarity threshold (distance >= 10).
    """
    err_file = (
        "Traceback (most recent call last):\n"
        "  File \"app.py\", line 12, in read_data\n"
        "    FileNotFoundError: Missing config schema"
    )
    err_type = (
        "Traceback (most recent call last):\n"
        "  File \"math_ops.py\", line 88, in calculate\n"
        "    ZeroDivisionError: division by zero in matrix inversion"
    )
    sim1 = compute_simhash(err_file)
    sim2 = compute_simhash(err_type)
    dist = hamming_distance(sim1, sim2)
    assert dist >= 10, f"Expected distinct errors to have distance >= 10, got {dist}"


def test_band_splitting_and_ranges():
    """Verify 4-band splitting partitions 64-bit int into four 16-bit unsigned ints."""
    sim = 0x123456789ABCDEF0
    b0, b1, b2, b3 = split_simhash_bands(sim)

    assert b0 == 0x1234
    assert b1 == 0x5678
    assert b2 == 0x9ABC
    assert b3 == 0xDEF0

    for b in (b0, b1, b2, b3):
        assert 0 <= b <= 0xFFFF

    # Reconstruct 64-bit int from bands
    reconstructed = (b0 << 48) | (b1 << 32) | (b2 << 16) | b3
    assert reconstructed == sim


def test_empty_and_non_string_input_safe():
    """Empty or non-string input safely returns 0 without raising."""
    assert compute_simhash("") == 0
    assert compute_simhash(None) == 0
    assert compute_simhash(12345) == 0
    b0, b1, b2, b3 = split_simhash_bands(0)
    assert (b0, b1, b2, b3) == (0, 0, 0, 0)
