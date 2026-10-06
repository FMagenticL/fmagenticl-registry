"""
Export the FMagenticL registry to a static patches/ directory.

Behavior:
    - If fmagenticl.db exists and contains a resolve_cache table, export
      from the database (authoritative source).
    - If fmagenticl.db is missing or the table is absent, exit cleanly
      with a message. Do NOT crash. The patches/ directory committed to
      the repository is the source of truth in that case, and the
      downstream build_distribution.py will use it directly.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

DB_PATH = "fmagenticl.db"
OUT_DIR = "patches"

LEGACY_KEYS = ("action", "key_path", "key_name")
KEEP_KEYS = (
    "patch_type",
    "target_file",
    "json_patch",
    "fallback_cli",
    "file_ops",
    "strategy",
    "mcp_substitution",
    "mcp_uri",
    "config_patch",
    "confidence",
)


def database_available(path: str) -> bool:
    if not os.path.exists(path):
        return False
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='resolve_cache'"
        )
        found = cur.fetchone() is not None
        conn.close()
        return found
    except sqlite3.DatabaseError:
        return False


def export_from_db(db_path: str, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    for f in os.listdir(out_dir):
        if f.endswith(".json"):
            os.remove(os.path.join(out_dir, f))

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM resolve_cache")
    rows = cur.fetchall()

    count = 0
    for row in rows:
        raw_fp = row["fingerprint"]
        fp_hex = raw_fp.replace("sha256:", "")
        try:
            patch_data = json.loads(row["patch_json"])
        except (ValueError, TypeError):
            continue
        for k in LEGACY_KEYS:
            patch_data.pop(k, None)
        patch_obj = {
            "fingerprint": f"sha256:{fp_hex}",
            "patch": {
                k: patch_data[k] for k in KEEP_KEYS if k in patch_data and patch_data[k] is not None
            },
            "confidence": row["confidence"],
            "submitted_by": row["submitted_by"],
            "verification_tier": row["verification_tier"],
            "foundational": bool(row["foundational"]),
            "is_quarantined": bool(row["is_quarantined"]),
        }
        out_path = Path(out_dir) / f"{fp_hex}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(patch_obj, f, indent=2, sort_keys=True)
        count += 1

    conn.close()
    return count


def main() -> int:
    if database_available(DB_PATH):
        count = export_from_db(DB_PATH, OUT_DIR)
        print(f"Exported {count} patches from {DB_PATH} into /{OUT_DIR}/")
        return 0

    existing = [f for f in os.listdir(OUT_DIR) if f.endswith(".json")] if os.path.isdir(OUT_DIR) else []
    if existing:
        print(
            f"Database not available at {DB_PATH}. Using existing {len(existing)} "
            f"patches in /{OUT_DIR}/ as source of truth. No export performed."
        )
        return 0

    print(
        f"FATAL: Database not available at {DB_PATH} and no patches found in /{OUT_DIR}/.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
