"""F2 (2026-11-25) — an unverifiable local snapshot must fail loudly, not silently egress.

Before this change, a bundled snapshot that failed signature verification was simply discarded
(`local_cache._load_snapshot` returned early), the tier-1 cache stayed empty, and every lookup
fell through to `_query_remote`. An integrity failure therefore became an outbound network call —
the exact opposite of the air-gapped behaviour this product is positioned on.

These tests assert the refusal, and include a positive control proving the guard (not something
else) is what prevents egress.
"""

import socket

import pytest

from fmagenticl.client.errors import FMagenticLIntegrityError
from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient

CANONICAL_FP = "009b5bbea23936ecfdf12e3ce4cee7fdc464f27cb778c2b46c2fd5edc3b0c5f0"


def _forbid_sockets(monkeypatch):
    """Record and fail any attempt to open a socket."""
    calls = []

    def _forbid(*args, **kwargs):
        calls.append(1)
        raise AssertionError("network egress attempted")

    monkeypatch.setattr(socket.socket, "connect", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)
    return calls


def test_air_gap_refuses_instead_of_egress(tmp_path, monkeypatch):
    """Air-gap ON: unverifiable snapshot -> typed refusal, zero socket calls."""
    monkeypatch.setattr(
        "fmagenticl.client.local_cache.verify_snapshot_file", lambda *a, **k: False
    )
    calls = _forbid_sockets(monkeypatch)

    cache = LocalCache(delta_path=str(tmp_path / "delta.json"))
    assert cache._snapshot_verification_failed is True, "verification failure must be recorded"

    client = FMagenticLClient(local_cache=cache, require_signature=True, air_gap=True)

    with pytest.raises(FMagenticLIntegrityError) as exc:
        client.resolve(CANONICAL_FP)

    assert "failed signature verification" in str(exc.value)
    assert calls == [], "air-gap mode must make zero outbound calls"
    assert client._metrics["integrity_refusal"] == 1


def test_failed_snapshot_without_air_gap_still_attempts_edge(tmp_path, monkeypatch):
    """Positive control: with the guard off, the old egress behaviour is restored.

    This is what makes the test above meaningful — without it, a vacuous pass (nothing attempted
    for an unrelated reason) would look identical to a real refusal.
    """
    monkeypatch.setattr(
        "fmagenticl.client.local_cache.verify_snapshot_file", lambda *a, **k: False
    )
    calls = _forbid_sockets(monkeypatch)

    cache = LocalCache(delta_path=str(tmp_path / "delta2.json"))
    client = FMagenticLClient(local_cache=cache, require_signature=True, air_gap=False)
    assert client.air_gap is False

    with pytest.raises(AssertionError):
        client.resolve(CANONICAL_FP)

    assert calls, "control must prove egress was attempted when air-gap is off"


def test_air_gap_defaults_on(monkeypatch, tmp_path):
    """No argument and no env var -> fail closed."""
    monkeypatch.delenv("FMAGENTICL_AIR_GAP", raising=False)
    client = FMagenticLClient(
        local_cache=LocalCache(delta_path=str(tmp_path / "delta3.json")),
        require_signature=True,
    )
    assert client.air_gap is True

    # Explicit opt-out via env still works.
    monkeypatch.setenv("FMAGENTICL_AIR_GAP", "0")
    client2 = FMagenticLClient(
        local_cache=LocalCache(delta_path=str(tmp_path / "delta4.json")),
        require_signature=True,
    )
    assert client2.air_gap is False
