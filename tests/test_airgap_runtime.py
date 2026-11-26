"""Zero-token offline socket-hook proof and air-gap cache-miss contract tests."""

import json
import socket
from pathlib import Path

from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_airgap_zero_network_on_init_hit_and_miss(tmp_path, monkeypatch):
    def _forbid_network(*args, **kwargs):
        raise AssertionError("Outbound network call is strictly forbidden in airgap mode")

    monkeypatch.setattr(socket.socket, "connect", _forbid_network)
    monkeypatch.setattr(socket, "create_connection", _forbid_network)

    snap_path = REPO_ROOT / "dist" / "v1" / "snapshot.json"
    cache = LocalCache(
        snapshot_path=str(snap_path),
        delta_path=str(tmp_path / "delta.json"),
        verify_signature=False,
    )
    client = FMagenticLClient(local_cache=cache, require_signature=False, air_gap=True)

    # Canonical bundled lookup makes 0 outbound socket connections
    sig = client.lookup_signature("SIG-2026-0001")
    assert sig is not None
    assert sig["id"] == "SIG-2026-0001"

    # Cache miss in air_gap=True returns None cleanly with 0 outbound socket connections
    miss = client.lookup_signature("SIG-9999-9999")
    assert miss is None


def test_outbound_telemetry_methods_refuse_in_airgap_default(tmp_path, monkeypatch):
    def _forbid_network(*args, **kwargs):
        raise AssertionError("Outbound network call is strictly forbidden in airgap mode")

    monkeypatch.setattr(socket.socket, "connect", _forbid_network)
    monkeypatch.setattr(socket, "create_connection", _forbid_network)

    cache = LocalCache(
        snapshot_path=str(REPO_ROOT / "dist" / "v1" / "snapshot.json"),
        delta_path=str(tmp_path / "delta.json"),
        verify_signature=False,
    )
    client = FMagenticLClient(local_cache=cache, require_signature=False)
    assert client.air_gap is True
    assert client.lookup_signature("CVE-2025-3248")["id"] == "SIG-2026-0048"
