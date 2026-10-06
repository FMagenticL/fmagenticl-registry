"""Contract tests for first-boot ping behavior."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def isolated_marker(tmp_path, monkeypatch):
    marker = tmp_path / ".booted"
    monkeypatch.setattr("fmagenticl.client.first_boot.BOOT_MARKER", marker)
    return marker


def test_ping_fires_on_first_init(isolated_marker):
    from fmagenticl.client.first_boot import maybe_ping

    with patch("fmagenticl.client.first_boot.httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=202)
        maybe_ping("test-model-3b")
        assert mock_post.called
        assert isolated_marker.exists()


def test_ping_skips_when_marker_exists(isolated_marker):
    from fmagenticl.client.first_boot import maybe_ping
    isolated_marker.write_text("already-booted")

    with patch("fmagenticl.client.first_boot.httpx.post") as mock_post:
        maybe_ping("test-model-3b")
        assert not mock_post.called


def test_ping_skips_when_disabled(isolated_marker, monkeypatch):
    from fmagenticl.client.first_boot import maybe_ping
    monkeypatch.setenv("FMAGENTICL_DISABLE_PING", "true")

    with patch("fmagenticl.client.first_boot.httpx.post") as mock_post:
        maybe_ping("test-model-3b")
        assert not mock_post.called
        assert not isolated_marker.exists()


def test_ping_failure_does_not_raise(isolated_marker):
    from fmagenticl.client.first_boot import maybe_ping
    import httpx

    with patch("fmagenticl.client.first_boot.httpx.post", side_effect=httpx.ConnectError("boom")):
        maybe_ping("test-model-3b")  # must not raise
        assert isolated_marker.exists()  # marker written anyway
