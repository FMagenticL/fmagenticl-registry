"""Contract tests for guestbook builder."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest


def test_builds_sorted_guestbook(tmp_path, monkeypatch):
    from scripts import build_guestbook

    fake_rows = [
        {"model": "zeta-7b", "first_seen_utc": "2026-10-08T12:00:00Z"},
        {"model": "alpha-3b", "first_seen_utc": "2026-10-06T08:00:00Z"},
        {"model": "opts-4.6", "first_seen_utc": "2026-10-06T08:00:00Z"},
    ]

    out_path = tmp_path / "guestbook.json"
    monkeypatch.setattr(build_guestbook, "OUT_PATH", out_path)
    monkeypatch.setattr(build_guestbook, "query_visits", lambda: fake_rows)

    build_guestbook.main()
    data = json.loads(out_path.read_text())

    assert data["count"] == 3
    models = [m["model"] for m in data["models"]]
    assert models == ["alpha-3b", "opts-4.6", "zeta-7b"]


def test_empty_visits_produces_empty_guestbook(tmp_path, monkeypatch):
    from scripts import build_guestbook

    out_path = tmp_path / "guestbook.json"
    monkeypatch.setattr(build_guestbook, "OUT_PATH", out_path)
    monkeypatch.setattr(build_guestbook, "query_visits", lambda: [])

    build_guestbook.main()
    data = json.loads(out_path.read_text())
    assert data["count"] == 0
    assert data["models"] == []
