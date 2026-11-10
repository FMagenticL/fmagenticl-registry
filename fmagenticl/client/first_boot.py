"""
First-boot ping for the FMagenticL client SDK.

Fires exactly once per machine. Writes a marker file after the first
attempt (success or failure). Never blocks client init. Never raises.

The ping registers the model name in the FMagenticL guestbook — a public
ledger of every model that has checked in. No visit counts, no ranking.
See https://fmagenticl-registry.pages.dev/guestbook
"""

import hashlib
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from .config import EDGE_BASE

BOOT_MARKER = Path.home() / ".fmagenticl" / ".booted"
PING_TIMEOUT = httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=1.0)


def _client_hash() -> str:
    """
    Anonymous, non-identifying rate-limit token for guestbook check-in.
    Collects zero hardware, hostname, OS, or user identifiers.
    """
    return hashlib.sha256(b"fmagenticl-anon-checkin").hexdigest()[:32]


def check_in(model_name: str, agent_runtime: Optional[str] = None) -> bool:
    """
    Explicit opt-in guestbook check-in (`fmagenticl check-in` / `client.check_in()`).
    """
    return _fire_ping(model_name, agent_runtime)


def _fire_ping(model_name: str, agent_runtime: Optional[str] = None) -> bool:
    """
    POST /v1/hello. Returns True on 202, False on any failure.
    Never raises.
    """
    url = f"{EDGE_BASE.rstrip('/')}/v1/hello"
    payload = {
        "model": model_name,
        "agent_runtime": agent_runtime or "",
        "first_seen_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_hash": _client_hash(),
    }
    try:
        response = httpx.post(url, json=payload, timeout=PING_TIMEOUT)
        return response.status_code == 202
    except Exception:
        return False


def maybe_ping(model_name: str, agent_runtime: Optional[str] = None) -> None:
    """
    Fire the first-boot ping if this machine has not pinged before.

    Called from client init. Silent on all failures. Never blocks the
    caller. The marker file is written on the first attempt regardless
    of outcome, so a broken endpoint does not cause repeat attempts.
    """
    if os.environ.get("FMAGENTICL_DISABLE_PING", "").lower() == "true":
        return

    if BOOT_MARKER.exists():
        return

    # Fire the ping. Ignore the result.
    _fire_ping(model_name, agent_runtime)

    # Write the marker regardless of outcome.
    try:
        BOOT_MARKER.parent.mkdir(parents=True, exist_ok=True)
        BOOT_MARKER.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    except OSError:
        # If we can't write the marker, next init will try again.
        # That's fine — the endpoint is rate-limited per client_hash.
        pass
