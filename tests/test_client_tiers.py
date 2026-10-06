"""
Test tiers for the FMagenticL client SDK read path.

Each tier has an explicit latency budget. These are assertions about
guaranteed behavior, not benchmarks.
"""

import time
from unittest.mock import patch

import pytest
from fmagenticl.client.local_cache import LocalCache


def test_memory_hit_latency():
    """Tier 1 — In-memory base snapshot hit (<1ms)."""
    cache = LocalCache()
    cache._memory["test_fp_warm"] = {"patch_type": "cli-override", "fallback_cli": "echo warm"}

    start = time.perf_counter()
    res = cache.get("test_fp_warm")
    duration_ms = (time.perf_counter() - start) * 1000

    assert res is not None
    assert res["fallback_cli"] == "echo warm"
    assert duration_ms < 2.0, f"Memory hit took {duration_ms:.3f}ms, expected < 2ms"


def test_delta_hit_latency(tmp_path):
    """Tier 2 — Local disk delta cache hit (<5ms)."""
    delta_file = str(tmp_path / "delta.json")
    cache = LocalCache(delta_path=delta_file)
    cache.put("test_fp_delta", {"patch_type": "cli-override", "fallback_cli": "echo delta"})

    start = time.perf_counter()
    res = cache.get("test_fp_delta")
    duration_ms = (time.perf_counter() - start) * 1000

    assert res is not None
    assert res["fallback_cli"] == "echo delta"
    assert duration_ms < 10.0, f"Delta hit took {duration_ms:.3f}ms, expected < 10ms"


def test_edge_fetch_mock(client_with_empty_cache):
    """
    Tier 3 — Edge fetch path returns the patch and completes well under
    the timeout budget. Patches at the client boundary so the measurement
    is Python-side overhead, not the OS network stack.
    """
    fake_patch = {
        "fingerprint": "sha256:deadbeef",
        "patch_type": "application/json-patch+json",
        "json_patch": [{"op": "remove", "path": "/engines"}],
        "confidence": 0.95,
        "submitted_by": "test",
        "verification_tier": "claimed",
        "foundational": False,
    }

    with patch.object(client_with_empty_cache, "_query_remote", return_value=fake_patch):
        start = time.perf_counter()
        result = client_with_empty_cache.resolve("deadbeef")
        elapsed_ms = (time.perf_counter() - start) * 1000

    assert result is not None
    assert result["fingerprint"] == "sha256:deadbeef"
    assert elapsed_ms < 200, f"Edge fetch path took {elapsed_ms:.2f}ms, expected <200ms"


def test_timeout_graceful_bypass(client_with_empty_cache):
    """
    Tier 4 — Unreachable edge returns None within the SLA window without
    raising. Locks the single-attempt contract.

    192.0.2.1 is RFC 5737 TEST-NET-1, reserved and unroutable.
    """
    client_with_empty_cache.edge_base = "http://192.0.2.1:9"

    start = time.perf_counter()
    result = client_with_empty_cache.resolve("deadbeef")
    elapsed = time.perf_counter() - start

    assert result is None
    assert elapsed < 2.0, f"Timeout path took {elapsed:.2f}s, expected <2.0s"


@pytest.fixture
def client_with_empty_cache(tmp_path, monkeypatch):
    from fmagenticl.client.local_cache import LocalCache
    from fmagenticl.client.middleware import MiddlewareClient

    empty_snapshot = tmp_path / "snapshot.json"
    empty_snapshot.write_text("{}")
    delta_cache = tmp_path / "delta_cache.json"
    monkeypatch.setenv("FMAGENTICL_DELTA_CACHE_PATH", str(delta_cache))

    cache = LocalCache(snapshot_path=str(empty_snapshot))
    return MiddlewareClient(local_cache=cache)
