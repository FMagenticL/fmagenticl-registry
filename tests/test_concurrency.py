"""Concurrent thread-safety tests for LocalCache and FMagenticLClient v3.0 lookups."""

import concurrent.futures
import json
from pathlib import Path

from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_concurrent_client_lookups_and_listing(tmp_path):
    cache = LocalCache(
        snapshot_path=str(REPO_ROOT / "dist" / "v1" / "snapshot.json"),
        delta_path=str(tmp_path / "delta.json"),
        verify_signature=False,
    )
    client = FMagenticLClient(local_cache=cache, require_signature=False, air_gap=True)
    ids = [f"SIG-2026-{i:04d}" for i in range(1, 61)]

    def _worker(sig_id: str):
        rec = client.lookup_signature(sig_id)
        assert rec is not None and rec["id"] == sig_id
        return rec["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(_worker, ids))
    assert len(results) == 60
