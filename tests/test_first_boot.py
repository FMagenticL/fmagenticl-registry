"""
Anti-Telemetry Contract Verification Suite.
Verifies that client initialization maintains a 100% passive, zero-trust posture:
- Zero network requests (HTTP, TCP socket, or DNS pings) on client instantiation.
- Zero telemetry marker files (.fmagenticl_ping, .booted) written to disk.
- Complete excision of covert first_boot ping logic.
"""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from fmagenticl.client.middleware import FMagenticLClient


def test_first_boot_module_is_deleted():
    """Verify that first_boot.py has been completely excised from the client package."""
    with pytest.raises(ModuleNotFoundError):
        import fmagenticl.client.first_boot  # noqa: F401


def test_zero_telemetry_on_client_init_auto_ping_false(tmp_path, monkeypatch):
    """Client init with default settings performs zero network calls and creates zero disk markers."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    with patch("httpx.post") as mock_httpx, \
         patch("urllib.request.urlopen") as mock_urllib, \
         patch("socket.socket") as mock_socket:

        client = FMagenticLClient(auto_ping=False)
        assert client is not None

        # Assert zero outbound network attempts across all standard network clients
        assert not mock_httpx.called
        assert not mock_urllib.called
        assert not mock_socket.called

        # Assert no telemetry marker files exist in home directory or tmp_path
        marker_files = list(tmp_path.glob(".*ping*")) + list(tmp_path.glob(".*boot*"))
        assert len(marker_files) == 0


def test_zero_telemetry_on_client_init_auto_ping_true_deprecated(tmp_path, monkeypatch):
    """Passing auto_ping=True is safely treated as a deprecated no-op without network transmission."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("FMAGENTICL_GUESTBOOK", "1")

    with patch("httpx.post") as mock_httpx, \
         patch("urllib.request.urlopen") as mock_urllib, \
         patch("socket.socket") as mock_socket:

        client = FMagenticLClient(auto_ping=True)
        assert client is not None

        # Zero network calls despite auto_ping=True and FMAGENTICL_GUESTBOOK=1
        assert not mock_httpx.called
        assert not mock_urllib.called
        assert not mock_socket.called

        # Zero marker files on disk
        marker_files = list(tmp_path.glob(".*ping*")) + list(tmp_path.glob(".*boot*"))
        assert len(marker_files) == 0


def test_zero_background_threads_spawned_on_init():
    """Verify client init does not spawn background daemon threads for telemetry."""
    import threading
    threads_before = threading.active_count()
    client = FMagenticLClient(auto_ping=True)
    threads_after = threading.active_count()
    assert threads_after == threads_before
    assert client is not None
