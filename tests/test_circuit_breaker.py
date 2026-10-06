import time
from unittest.mock import patch
import requests
from fmagenticl.client.middleware import FMagenticLClient, CircuitBreaker

def test_circuit_breaker_transitions():
    cb = CircuitBreaker(failure_threshold=3, reset_timeout=0.08)
    cb.record_success()  # Ensure clean starting state
    assert cb.state == "CLOSED"
    assert cb.can_request() is True

    # 1. Record 3 failures -> Transitions to OPEN
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "CLOSED"
    cb.record_failure()
    assert cb.state == "OPEN"
    assert cb.can_request() is False

    # 2. Fast-fail locally (0ms) while OPEN
    t0 = time.perf_counter()
    assert cb.can_request() is False
    assert (time.perf_counter() - t0) < 0.005

    # 3. Wait for reset timeout -> Transitions to HALF_OPEN
    time.sleep(0.12)
    assert cb.can_request() is True
    assert cb.state == "HALF_OPEN"

    # 4. Success restores state to CLOSED
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.failure_count == 0

def test_client_circuit_breaker_integration(tmp_path):
    cache_path = str(tmp_path / "cache.json")
    cb = CircuitBreaker(failure_threshold=2, reset_timeout=0.2)
    cb.record_success()  # Ensure clean state

    client = FMagenticLClient(
        api_base="http://invalid.fmagenticl.domain:9999",
        local_cache_path=cache_path,
        circuit_breaker=cb,
        circuit_failure_threshold=2,
        circuit_reset_timeout=0.2,
        timeout=0.05
    )

    env = {"os": "win32", "runtime": "node@24.15.0"}
    fail = {"error_code": "NET_TEST", "exit_code": 1}

    # Trigger 2 failures to trip circuit
    client.resolve_failure(env, fail)
    client.resolve_failure(env, fail)
    assert client.circuit_breaker.state == "OPEN"

    # Subsequent call fails immediately without network request
    t_start = time.perf_counter()
    res = client.resolve_failure(env, fail)
    elapsed = time.perf_counter() - t_start
    assert res is None
    assert elapsed < 0.01  # Instant 0ms drop

    # Clean up singleton state
    cb.record_success()
