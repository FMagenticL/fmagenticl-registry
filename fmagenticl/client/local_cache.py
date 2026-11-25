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

import copy
import json
import os
import tempfile
import threading
import time
from typing import Optional, Tuple

from fmagenticl.client.verify import verify_snapshot_file


class LocalCache:
    def __init__(
        self,
        snapshot_path: str = "snapshot.json",
        delta_path: Optional[str] = None,
        cache_path: Optional[str] = None,
        verify_signature: bool = True,
        sig_path: Optional[str] = None,
        public_key_b64: Optional[str] = None,
    ):
        if snapshot_path is None or snapshot_path == "snapshot.json":
            bundled = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                "snapshot.json",
            )
            self.snapshot_path = bundled if os.path.exists(bundled) else "snapshot.json"
        else:
            self.snapshot_path = snapshot_path
        self.delta_path = delta_path or cache_path or os.environ.get(
            "FMAGENTICL_DELTA_CACHE_PATH",
            os.path.join(os.path.expanduser("~"), ".fmagenticl", "delta_cache.json"),
        )
        self.verify_signature = (
            verify_signature
            if os.environ.get("FMAGENTICL_VERIFY_SIGNATURES", "1") != "0"
            else False
        )
        self.sig_path = sig_path
        if not self.sig_path and self.snapshot_path:
            cand = self.snapshot_path.rsplit(".json", 1)[0] + ".sig" if self.snapshot_path.endswith(".json") else self.snapshot_path + ".sig"
            if os.path.exists(cand):
                self.sig_path = cand
        self.public_key_b64 = public_key_b64
        self._lock = threading.Lock()
        self._memory: dict = {}
        self._aliases: dict = {}
        self._delta: dict = {}
        self._snapshot_signature_verified: bool = False
        # F2: distinguishes "no snapshot shipped" (harmless, edge-only mode) from
        # "snapshot present but failed verification" (an integrity event to report).
        self._snapshot_verification_failed: bool = False
        self._load_snapshot()
        self._load_delta()

    def _load_snapshot(self) -> None:
        if not self.snapshot_path or not os.path.exists(self.snapshot_path):
            self._snapshot_verification_failed = False
            return

        snap_sig_ok = False
        if self.verify_signature:
            if not verify_snapshot_file(
                self.snapshot_path,
                sig_path=self.sig_path,
                public_key_b64=self.public_key_b64,
            ):
                # Fail closed: never trust unverified data - but record *why* the cache is
                # empty, so the client can refuse loudly instead of silently going online.
                self._snapshot_verification_failed = True
                return
            snap_sig_ok = True

        try:
            with open(self.snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            patches = data.get("patches", {}) if isinstance(data, dict) else {}
            raw_aliases = data.get("aliases", {}) if isinstance(data, dict) else {}
            clean_aliases = {
                str(k).replace("sha256:", "").strip().lower(): str(v).replace("sha256:", "").strip().lower()
                for k, v in raw_aliases.items()
            } if isinstance(raw_aliases, dict) else {}
            with self._lock:
                self._memory = patches
                self._aliases = clean_aliases
                self._snapshot_signature_verified = snap_sig_ok
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

    def resolve_alias(self, fp_hex: str) -> str:
        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        with self._lock:
            return self._aliases.get(clean_hex, clean_hex)

    def get_with_source(self, fp_hex: str) -> Tuple[Optional[dict], bool, str]:
        """Return (deepcopy(patch), from_memory, canonical_fp_hex)."""
        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        with self._lock:
            for k in (clean_hex, fp_hex, f"sha256:{clean_hex}"):
                if k in self._memory:
                    return copy.deepcopy(self._memory[k]), True, clean_hex
            alias_target = self._aliases.get(clean_hex)
            if alias_target:
                for k in (alias_target, f"sha256:{alias_target}"):
                    if k in self._memory:
                        return copy.deepcopy(self._memory[k]), True, alias_target
            for k in (clean_hex, fp_hex, f"sha256:{clean_hex}"):
                if k in self._delta:
                    return copy.deepcopy(self._delta[k]), False, clean_hex
        return None, False, clean_hex

    def get(self, fp_hex: str) -> Optional[dict]:
        patch, _, _ = self.get_with_source(fp_hex)
        return patch

    def put(self, fp_hex: str, patch: dict) -> None:
        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        with self._lock:
            self._delta[clean_hex] = copy.deepcopy(patch)
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
