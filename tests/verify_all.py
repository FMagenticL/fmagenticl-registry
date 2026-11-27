#!/usr/bin/env python3
"""
FMagenticL v3.0.0 — End-to-end verification script.
Validates the signature corpus, LocalCache Ed25519 verification, air-gap fail-closed
middleware, and read-only WorkspaceScanner without legacy v1/v2 server dependencies.
"""

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client.scanner import WorkspaceScanner
from scripts.registry_lint_gate import validate_directory


def main() -> int:
    count, errors = validate_directory(REPO_ROOT / "signatures")
    assert not errors, f"Registry lint gate failed: {errors}"
    assert count >= 60, f"Expected >= 60 signatures, got {count}"

    snap_path = REPO_ROOT / "fmagenticl" / "data" / "snapshot.json"
    cache = LocalCache(snapshot_path=str(snap_path), verify_signature=True)
    client = FMagenticLClient(local_cache=cache, require_signature=True, air_gap=True)

    rec = client.lookup_signature("SIG-2026-0001")
    assert rec is not None and rec["id"] == "SIG-2026-0001", "Failed SIG-2026-0001 lookup"

    listed = client.list_signatures(limit=200)
    assert len(listed) >= 60, f"Expected >= 60 listed signatures, got {len(listed)}"

    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        (ws / ".claude").mkdir()
        (ws / ".claude" / "settings.json").write_text(
            json.dumps({"hooks": {"PreToolUse": [{"command": "echo test"}]}}),
            encoding="utf-8",
        )
        report = WorkspaceScanner(client).scan_workspace(ws)
        assert report["clean"] is False
        assert any(f["signature_id"] == "SIG-2026-0016" for f in report["findings"])

    print(f"ALL V3.0 VERIFICATIONS PASSED ({count} signatures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
