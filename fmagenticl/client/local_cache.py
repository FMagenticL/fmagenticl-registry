"""
Local cache for the FMagenticL client SDK.

Two tiers of storage:
    - In-memory dict, populated from the bundled snapshot at init.
    - On-disk delta cache, populated by edge fetches during runtime.

Lookup order is: memory, then delta cache. Miss falls through to the
middleware's edge-fetch path.

Writes to the delta cache are atomic (temp file + os.replace) with
retry backoff to handle Windows file-lock contention.
"""

import json
import os
import tempfile
import threading
import time
from typing import Optional


class LocalCache:
    def __init__(
        self,
        snapshot_path: str = "snapshot.json",
        delta_path: Optional[str] = None,
        cache_path: Optional[str] = None,
    ):
        self.snapshot_path = snapshot_path
        self.delta_path = delta_path or cache_path or os.environ.get(
            "FMAGENTICL_DELTA_CACHE_PATH",
            os.path.join(os.path.expanduser("~"), ".fmagenticl", "delta_cache.json"),
        )
        self._lock = threading.Lock()
        self._memory: dict = {}
        self._delta: dict = {}
        self._load_snapshot()
        self._load_delta()

    def _load_snapshot(self) -> None:
        if not os.path.exists(self.snapshot_path):
            return
        try:
            with open(self.snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            patches = data.get("patches", {}) if isinstance(data, dict) else {}
            with self._lock:
                self._memory = patches
        except (OSError, ValueError):
            # Snapshot unreadable. Operate in edge-only mode.
            pass

    def _load_delta(self) -> None:
        if not os.path.exists(self.delta_path):
            return
        try:
            with open(self.delta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                self._delta = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            pass

    def _save_delta(self) -> None:
        os.makedirs(os.path.dirname(self.delta_path), exist_ok=True)
        for attempt in range(3):
            try:
                fd, tmp_path = tempfile.mkstemp(
                    dir=os.path.dirname(self.delta_path),
                    suffix=".tmp",
                )
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._delta, f)
                os.replace(tmp_path, self.delta_path)
                return
            except OSError:
                time.sleep(0.05 * (2 ** attempt))
        # Final attempt without atomicity; accept the risk rather than lose data.
        try:
            with open(self.delta_path, "w", encoding="utf-8") as f:
                json.dump(self._delta, f)
        except OSError:
            pass

    def get(self, fp_hex: str) -> Optional[dict]:
        clean_hex = fp_hex.replace("sha256:", "")
        with self._lock:
            for k in (clean_hex, fp_hex, f"sha256:{clean_hex}"):
                if k in self._memory:
                    return self._memory[k]
                if k in self._delta:
                    return self._delta[k]
        return None

    def put(self, fp_hex: str, patch: dict) -> None:
        clean_hex = fp_hex.replace("sha256:", "")
        with self._lock:
            self._delta[clean_hex] = patch
        self._save_delta()

    def resolve(self, fp_hex: str) -> Optional[dict]:
        """Backward-compatible alias for get()."""
        return self.get(fp_hex)

    def store(self, fp_hex: str, patch: dict) -> None:
        """Backward-compatible alias for put()."""
        self.put(fp_hex, patch)

    def stats(self) -> dict:
        with self._lock:
            return {
                "memory_entries": len(self._memory),
                "delta_entries": len(self._delta),
            }
