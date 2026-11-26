"""Fingerprint contract tests between signatures/*.json and dist/v1/snapshot.json."""

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_signature_fingerprints_match_snapshot_and_resolve_shards():
    snap = json.loads((REPO_ROOT / "dist" / "v1" / "snapshot.json").read_text(encoding="utf-8"))
    for sf in sorted((REPO_ROOT / "signatures").glob("SIG-2026-*.json")):
        rec = json.loads(sf.read_text(encoding="utf-8"))
        expected_hex = hashlib.sha256(rec["id"].encode("utf-8")).hexdigest()
        assert rec["fingerprint"] == f"sha256:{expected_hex}"
        assert expected_hex in snap["patches"]
        assert (REPO_ROOT / "dist" / "v1" / "resolve" / f"{expected_hex}.json").exists()
        assert (REPO_ROOT / "dist" / "v1" / "signatures" / f"{rec['id']}.json").exists()
