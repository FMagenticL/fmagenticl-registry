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


import subprocess
from datetime import datetime, timezone


def export_from_remote_d1(dist_dir: str = "dist") -> int:
    """
    Export committed grievances from Cloudflare D1 to dist/grievances.json
    so the static edge CDN and landing page have an immediate, un-gated snapshot.
    """
    os.makedirs(dist_dir, exist_ok=True)
    PURGE_GRIEVANCE_IDS = {
        'grv_gh_langchain-ai_langchain_41450', 'grv_gh_langchain-ai_langchain_41291',
        'grv_gh_cloudflare_workers-sdk_16237', 'grv_gh_cloudflare_workers-sdk_16141',
        'grv_gh_modelcontextprotocol_python-sdk_3586', 'grv_gh_modelcontextprotocol_typescript-sdk_2864',
        '82e4376c-3763-4e24-a37c-4a963a11295b', '90a44e12-9311-42e6-b1fa-5f9f459fc295',
        '7bab327e-20a8-446-8344-7546f8c8ccb0', '7bab327e-20a8-446e-8344-7546f8c8ccb0', '9d6f4f79-ca6c-4803-afe0-37757b741ef7'
    }

    cmd = [
        "wrangler", "d1", "execute", "fmagenticl-registry",
        "--remote", "--json",
        "--command", "SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, submitted_by, verification_tier, applies_to, created_at FROM grievances WHERE queue_status = 'committed' ORDER BY created_at DESC LIMIT 200",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            payload = json.loads(res.stdout)
            if isinstance(payload, list) and payload and "results" in payload[0]:
                results = payload[0]["results"]
                out_path = Path(dist_dir) / "grievances.json"

                # Merge existing grievances so committed/harvested items are preserved
                existing_map = {}
                if out_path.exists():
                    try:
                        prev = json.loads(out_path.read_text(encoding="utf-8"))
                        for g in prev.get("grievances", []):
                            gid = g.get("id")
                            if gid and gid not in PURGE_GRIEVANCE_IDS:
                                existing_map[gid] = g
                    except Exception:
                        pass
                for r in results:
                    gid = r.get("id")
                    if gid and gid not in PURGE_GRIEVANCE_IDS:
                        existing_map[gid] = r

                merged_results = list(existing_map.values())
                for g in merged_results:
                    g.pop("queue_status", None)
                merged_results.sort(key=lambda x: x.get("created_at") or "", reverse=True)

                data = {
                    "version": "1.0.0",
                    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "count": len(merged_results),
                    "grievances": merged_results,
                }
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, sort_keys=True)
                print(f"Exported {len(merged_results)} merged grievances to {out_path}")
                return len(merged_results)
    except Exception as e:
        print(f"Notice: Remote D1 grievance export skipped ({e}).", file=sys.stderr)

    # Fallback: ensure dist/grievances.json exists
    fallback_path = Path(dist_dir) / "grievances.json"
    if not fallback_path.exists():
        fallback_data = {
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": 0,
            "grievances": [],
        }
        with open(fallback_path, "w", encoding="utf-8") as f:
            json.dump(fallback_data, f, indent=2)
    return 0


def main() -> int:
    if os.environ.get("CLOUDFLARE_API_TOKEN") or "--remote-d1" in sys.argv:
        export_from_remote_d1("dist")

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

