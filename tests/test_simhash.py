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


def test_python_node_esm_simhash_parity_50_real_symptoms():
    """Verify exact Python <-> Node ESM compute_grievance_simhash_bands parity across 50 real symptoms."""
    import json
    import shutil
    import subprocess
    from pathlib import Path
    from fmagenticl.client.simhash import compute_grievance_simhash_bands

    repo_root = Path(__file__).resolve().parent.parent
    wrk_data = json.loads((repo_root / "dist" / "workarounds.json").read_text(encoding="utf-8"))
    symptoms = [item.get("symptom", "") for item in wrk_data.get("workarounds", []) if item.get("symptom")][:50]
    assert len(symptoms) == 50

    py_bands = [list(compute_grievance_simhash_bands(s)) for s in symptoms]
    mcp_uri = (repo_root / "functions" / "mcp.js").as_uri()
    node = shutil.which("node") or "node"
    script = f"""
      const mcp = await import({json.dumps(mcp_uri)});
      const out = {json.dumps(symptoms)}.map(s => {{
        const norm = mcp.normalizeErrorString(s);
        const h = mcp.computeSimhash64(norm);
        return mcp.splitSimhashBands(h);
      }});
      process.stdout.write(JSON.stringify(out));
    """
    res = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, encoding="utf-8", check=True, timeout=30)
    js_bands = json.loads(res.stdout)
    assert py_bands == js_bands


def test_held_out_mutated_symptom_lsh_recall():
    """Verify >= 90% LSH recall (band match & Hamming <= 3) across volatile env/line/hex/path/semver variations."""
    import json
    import re
    from pathlib import Path
    from fmagenticl.client.simhash import compute_grievance_simhash_bands

    repo_root = Path(__file__).resolve().parent.parent
    wrk_data = json.loads((repo_root / "dist" / "workarounds.json").read_text(encoding="utf-8"))
    symptoms = [
        item["symptom"] for item in wrk_data.get("workarounds", [])
        if isinstance(item.get("symptom"), str)
        and re.fullmatch(r"[\x20-\x7e]{50,}", item["symptom"])
        and len(item["symptom"].split()) >= 8
    ][:30]
    assert len(symptoms) >= 20

    def _bands_to_u64(bands):
        return (bands[0] << 48) | (bands[1] << 32) | (bands[2] << 16) | bands[3]

    hits = 0
    for idx, sym in enumerate(symptoms):
        # Simulate two runs of the same real failure under different CI runners / timestamps / offsets / patch versions
        trace_a = (
            f"2026-09-01T01:02:03Z C:\\Users\\alice\\app.py:{10 + idx}:4 "
            f"0x7f112233 v2.4.1 {sym}"
        )
        trace_b = (
            f"2026-11-19T14:22:33Z /home/runner/app.py:{900 + idx}:12 "
            f"0x99aabbcc v2.4.9 {sym}"
        )
        b_orig = compute_grievance_simhash_bands(trace_a)
        b_mut = compute_grievance_simhash_bands(trace_b)
        dist = hamming_distance(_bands_to_u64(b_orig), _bands_to_u64(b_mut))
        band_hit = any(b_orig[k] == b_mut[k] for k in range(4))
        if band_hit and dist <= 3:
            hits += 1

    assert (hits / len(symptoms)) >= 0.90, f"SimHash LSH recall too low: {hits}/{len(symptoms)}"
