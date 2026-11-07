"""
Export the FMagenticL registry to a static patches/ directory and paginate D1 grievances.

Behavior:
    - Remote Cloudflare D1 grievances are exported via paginated 1,000-row batches
      (eliminating the 1,000-row truncation ceiling) into dist/grievances.json and dist/workarounds.json.
    - If fmagenticl.db exists and contains a resolve_cache table, export
      from the database (authoritative source).
    - Otherwise, preserve existing committed patches/ as source of truth.
"""

import json
import os
import sqlite3
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

try:
    from scripts.fetch_cf_analytics import resolve_token, D1_DATABASE_ID
except Exception:
    def resolve_token():
        return os.environ.get("CLOUDFLARE_API_TOKEN", "")
    D1_DATABASE_ID = "8f0f1fae-2d36-4361-a547-26c0aa08d23d"

ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "f83dbbaa261d9ceac1f9f666fa9bd07b"


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


def _fetch_d1_page(sql: str, token: str) -> list[dict] | None:
    if token:
        try:
            url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{D1_DATABASE_ID}/query"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "FMagenticL-StaticExport/1.4.1",
            }
            payload = json.dumps({"sql": sql}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for block in data.get("result", []):
                    if "results" in block:
                        return block["results"]
        except Exception as e:
            print(f"Notice: Direct D1 REST export error ({e}), trying wrangler CLI...", file=sys.stderr)

    cmd = [
        "wrangler", "d1", "execute", "fmagenticl-registry",
        "--remote", "--json",
        "--command", sql,
    ]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            shell=(sys.platform == "win32"),
            timeout=30,
        )
        if res.returncode == 0:
            payload = json.loads(res.stdout)
            if isinstance(payload, list) and payload and "results" in payload[0]:
                return payload[0]["results"]
    except Exception as e:
        print(f"Notice: Remote D1 grievance export skipped ({e}).", file=sys.stderr)
    return None


def export_from_remote_d1(dist_dir: str = "dist") -> int:
    """
    Export all committed PROMOTED grievances from Cloudflare D1 using paginated 1,000-row
    queries into dist/grievances.json and dist/workarounds.json.
    """
    os.makedirs(dist_dir, exist_ok=True)
    PURGE_GRIEVANCE_IDS = {
        "grv_gh_langchain-ai_langchain_41450", "grv_gh_langchain-ai_langchain_41291",
        "grv_gh_cloudflare_workers-sdk_16237", "grv_gh_cloudflare_workers-sdk_16141",
        "grv_gh_modelcontextprotocol_python-sdk_3586", "grv_gh_modelcontextprotocol_typescript-sdk_2864",
        "82e4376c-3763-4e24-a37c-4a963a11295b", "90a44e12-9311-42e6-b1fa-5f9f459fc295",
        "7bab327e-20a8-446-8344-7546f8c8ccb0", "7bab327e-20a8-446e-8344-7546f8c8ccb0",
        "9d6f4f79-ca6c-4803-afe0-37757b741ef7",
        "grv_osv_PYSEC_2021_47", "grv_osv_GHSA_5jqp_qgf6_3pvh", "grv_osv_GHSA_8h2j_cgx8_6xv7",
        "grv_osv_GHSA_8c93_4hch_xgxp", "grv_osv_GHSA_8h5w_f6q9_wg35", "grv_osv_GHSA_cfph_4qqh_w828",
        "grv_osv_GHSA_f8mp_x433_5wpf", "grv_osv_PYSEC_2024_38", "grv_osv_GHSA_mr82_8j83_vxmv",
        "grv_osv_GHSA_3hjh_jh2h_vrg6", "grv_osv_GHSA_f2jm_rw3h_6phg", "grv_osv_PYSEC_2025_245",
        "grv_osv_GHSA_v3c8_3pr6_gr7p", "grv_osv_GHSA_5hq9_5r78_2gjh", "grv_osv_GHSA_pc6w_59fv_rh23",
        "grv_osv_GHSA_59p9_h35m_wg4g", "grv_osv_GHSA_7f5h_v6xp_fcq8", "grv_osv_GHSA_c67j_w6g6_q2cm",
    }
    purge_backup_dir = REPO_ROOT / "data" / "purge_backups"
    if purge_backup_dir.exists():
        for bkp in purge_backup_dir.glob("*.json"):
            try:
                bdata = json.loads(bkp.read_text(encoding="utf-8"))
                for row in bdata.get("rows", []):
                    if row.get("id"):
                        PURGE_GRIEVANCE_IDS.add(row["id"])
            except Exception:
                pass

    token = resolve_token()
    page_size = 1000
    offset = 0
    all_rows: list[dict] = []
    fetched_any = False

    while offset < 50000:
        sql = (
            "SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, "
            "environment_json, submitted_by, verification_tier, applies_to, created_at "
            "FROM grievances "
            "WHERE queue_status = 'PROMOTED' AND verification_tier IN ("
            "'verified_merged_pr', 'reporter_verified', 'internal_forensic_verified', "
            "'cryptographic_proof', 'osv_verified', 'verified_release') "
            f"ORDER BY created_at DESC, id DESC LIMIT {page_size} OFFSET {offset}"
        )
        batch = _fetch_d1_page(sql, token)
        if batch is None:
            break
        fetched_any = True
        all_rows.extend(batch)
        if len(batch) < page_size:
            break
        offset += page_size

    if fetched_any:
        out_path = Path(dist_dir) / "grievances.json"
        workarounds_path = Path(dist_dir) / "workarounds.json"

        existing_map: dict[str, dict] = {}
        prev_grievances: list[dict] = []
        source_path = workarounds_path if workarounds_path.exists() else out_path
        if source_path.exists():
            try:
                prev = json.loads(source_path.read_text(encoding="utf-8"))
                prev_grievances = prev.get("workarounds", prev.get("grievances", []))
                for g in prev_grievances:
                    gid = g.get("id")
                    if gid and gid not in PURGE_GRIEVANCE_IDS:
                        existing_map[gid] = g
            except Exception:
                pass

        for r in all_rows:
            gid = r.get("id")
            if not gid or gid in PURGE_GRIEVANCE_IDS:
                continue
            if r.get("verification_tier") == "osv_verified" and (r.get("created_at") or "") < "2026-01-01":
                continue
            wa_txt = (r.get("workaround") or "").strip()
            sym_txt = (r.get("symptom") or "").strip()
            if len(wa_txt) < 15 or wa_txt == sym_txt:
                continue
            existing_map[gid] = r

        merged_results = list(existing_map.values())
        for g in merged_results:
            g.pop("queue_status", None)
        merged_results.sort(key=lambda x: (x.get("created_at") or "", x.get("id") or ""), reverse=True)

        if out_path.exists() and workarounds_path.exists() and prev_grievances == merged_results:
            print(f"Grievances & workarounds unchanged (count: {len(merged_results)}). Preserving existing generated_at timestamp.")
            return len(merged_results)

        data = {
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(merged_results),
            "workarounds": merged_results,
            "grievances": merged_results,
        }
        serialized = json.dumps(data, indent=2, sort_keys=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(serialized)
        with open(workarounds_path, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"Exported {len(merged_results)} merged grievances/workarounds (fetched {len(all_rows)} rows from D1 across {offset // page_size + 1} page(s)) to {out_path} and {workarounds_path}")
        return len(merged_results)
    else:
        print("Notice: No remote D1 results returned to export.", file=sys.stderr)

    fallback_path = Path(dist_dir) / "grievances.json"
    fallback_workarounds_path = Path(dist_dir) / "workarounds.json"
    if not fallback_path.exists() or not fallback_workarounds_path.exists():
        fallback_data = {
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": 0,
            "workarounds": [],
            "grievances": [],
        }
        serialized_fallback = json.dumps(fallback_data, indent=2)
        if not fallback_path.exists():
            with open(fallback_path, "w", encoding="utf-8") as f:
                f.write(serialized_fallback)
        if not fallback_workarounds_path.exists():
            with open(fallback_workarounds_path, "w", encoding="utf-8") as f:
                f.write(serialized_fallback)
    return 0


def main() -> int:
    if resolve_token() or os.environ.get("CLOUDFLARE_API_TOKEN") or "--remote-d1" in sys.argv:
        export_from_remote_d1("dist")

    if "--from-local-sqlite" in sys.argv and database_available(DB_PATH):
        count = export_from_db(DB_PATH, OUT_DIR)
        print(f"Exported {count} patches from {DB_PATH} into /{OUT_DIR}/")
        return 0

    existing = [f for f in os.listdir(OUT_DIR) if f.endswith(".json")] if os.path.isdir(OUT_DIR) else []
    if existing:
        print(
            f"Using existing {len(existing)} committed patches in /{OUT_DIR}/ as source of truth."
        )
        return 0

    print(
        f"FATAL: Database not available at {DB_PATH} and no patches found in /{OUT_DIR}/.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
