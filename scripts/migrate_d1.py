"""
Idempotent D1 schema migration and chunked SimHash backfill CLI.
Safe to run repeatedly; no-op when AGENT_FRICTION & simhash_b0..b3 are already populated.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DB_NAME = "fmagenticl-registry"
D1_DATABASE_ID = "8f0f1fae-2d36-4361-a547-26c0aa08d23d"
DEFAULT_ACCOUNT_ID = "f83dbbaa261d9ceac1f9f666fa9bd07b"


def _extract_wrangler_json(stdout: str) -> Optional[Any]:
    start_arr, end_arr = stdout.find("["), stdout.rfind("]")
    if start_arr != -1 and end_arr > start_arr:
        try:
            return json.loads(stdout[start_arr : end_arr + 1])
        except Exception:
            pass
    start_obj, end_obj = stdout.find("{"), stdout.rfind("}")
    if start_obj != -1 and end_obj > start_obj:
        try:
            return json.loads(stdout[start_obj : end_obj + 1])
        except Exception:
            pass
    return None


def _run_wrangler_d1(args_list: List[str]) -> subprocess.CompletedProcess:
    wrangler_bin = shutil.which("wrangler") or "wrangler"
    return subprocess.run(
        [wrangler_bin, "d1", "execute", DB_NAME, "--remote", "-y", *args_list],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=(sys.platform == "win32"),
        check=False,
        timeout=60,
    )


def migrate_if_needed() -> None:
    result = _run_wrangler_d1([
        "--json",
        "--command", "SELECT sql FROM sqlite_master WHERE type='table' AND name='grievances'",
    ])
    if result.returncode != 0:
        print(f"Notice: Failed to query D1 table schema: {result.stderr}", file=sys.stderr)
        return

    payload = _extract_wrangler_json(result.stdout or "")
    if payload is None:
        print("Notice: Could not parse D1 JSON output.", file=sys.stderr)
        return

    sql = ""
    if isinstance(payload, list) and payload and "results" in payload[0]:
        results = payload[0]["results"]
        if results:
            sql = results[0].get("sql", "")

    if not sql:
        print("grievances table does not exist yet. schema.sql will create it.")
        return

    if "AGENT_FRICTION" in sql:
        print("D1 grievances table already contains AGENT_FRICTION in CHECK constraint. No migration needed.")
        return

    print("Migrating grievances table to include AGENT_FRICTION...")
    migration_sql = """
CREATE TABLE IF NOT EXISTS grievances_new (
    id TEXT PRIMARY KEY,
    grievance_type TEXT NOT NULL CHECK (grievance_type IN (
        'INFRASTRUCTURE_FRICTION',
        'PATCH_DISPUTE',
        'ENVIRONMENT_MISMATCH',
        'PROTOCOL_FRICTION',
        'HUMAN_OPERATOR_FRICTION',
        'AGENT_FRICTION'
    )),
    target TEXT NOT NULL,
    harness TEXT,
    fingerprint TEXT,
    symptom TEXT NOT NULL,
    workaround TEXT NOT NULL,
    environment_json TEXT,
    submitted_by TEXT NOT NULL,
    verification_tier TEXT NOT NULL,
    applies_to TEXT,
    simhash_b0 INTEGER,
    simhash_b1 INTEGER,
    simhash_b2 INTEGER,
    simhash_b3 INTEGER,
    created_at TEXT NOT NULL,
    queue_status TEXT NOT NULL DEFAULT 'committed'
);

INSERT INTO grievances_new (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status)
SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status FROM grievances;

DROP TABLE grievances;

ALTER TABLE grievances_new RENAME TO grievances;

CREATE INDEX IF NOT EXISTS idx_grievances_target ON grievances (target);
CREATE INDEX IF NOT EXISTS idx_grievances_type ON grievances (grievance_type);
CREATE INDEX IF NOT EXISTS idx_grievances_fingerprint ON grievances (fingerprint);
CREATE INDEX IF NOT EXISTS idx_grievances_created ON grievances (created_at);
CREATE INDEX IF NOT EXISTS idx_grievances_b0 ON grievances (simhash_b0);
CREATE INDEX IF NOT EXISTS idx_grievances_b1 ON grievances (simhash_b1);
CREATE INDEX IF NOT EXISTS idx_grievances_b2 ON grievances (simhash_b2);
CREATE INDEX IF NOT EXISTS idx_grievances_b3 ON grievances (simhash_b3);
"""
    tmp_path = "temp_migration_agent_friction.sql"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(migration_sql)
        run_res = _run_wrangler_d1([f"--file={tmp_path}"])
        if run_res.returncode == 0:
            print("Successfully migrated grievances table to support AGENT_FRICTION.")
        else:
            print(f"Notice: Migration output: {run_res.stderr.strip()}", file=sys.stderr)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def normalize_model_attributions() -> None:
    norm_sql = (
        "UPDATE visits SET model = 'deepseek-v4.1' WHERE model = 'v4.1';\n"
        "UPDATE visits SET model = 'deepseek-v3' WHERE model IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek');\n"
        "UPDATE grievances SET submitted_by = 'deepseek-v4.1' WHERE submitted_by = 'v4.1';\n"
        "UPDATE grievances SET submitted_by = 'deepseek-v3' WHERE submitted_by IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek');\n"
        "UPDATE telemetry SET submitted_by = 'deepseek-v4.1' WHERE submitted_by = 'v4.1';\n"
        "UPDATE telemetry SET submitted_by = 'deepseek-v3' WHERE submitted_by IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek', 'anonymous');\n"
    )
    tmp_path = "temp_norm_attributions.sql"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(norm_sql)
        run_res = _run_wrangler_d1([f"--file={tmp_path}"])
        if run_res.returncode == 0:
            print("Successfully normalized model attributions in D1.")
        else:
            print(f"Attribution normalization notice: {run_res.stderr}", file=sys.stderr)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def purge_bleed_and_synthetic_rows() -> None:
    purge_sql = (
        "DELETE FROM grievances WHERE id IN ('grv_gh_langchain-ai_langchain_41450', 'grv_gh_langchain-ai_langchain_41291', 'grv_gh_cloudflare_workers-sdk_16237', 'grv_gh_cloudflare_workers-sdk_16141', 'grv_gh_modelcontextprotocol_python-sdk_3586', 'grv_gh_modelcontextprotocol_typescript-sdk_2864', '82e4376c-3763-4e24-a37c-4a963a11295b', '90a44e12-9311-42e6-b1fa-5f9f459fc295', '7bab327e-20a8-4468-8344-7546f8c8ccb0', '7bab327e-20a8-446e-8344-7546f8c8ccb0', '9d6f4f79-ca6c-4803-afe0-37757b741ef7');\n"
        "DELETE FROM telemetry WHERE fingerprint IN ('sha256:1c9a53a5f918e1edab53f58f449bca639377e3ebe791e9be4dc7a7fe42c01574', 'sha256:5efc208e3408e7cf4f712be6f6de5942755dcb367d17d459ff93d12156ac8073', 'sha256:694d8f696a95c3bc032d146f5a73e4d1fb90536c888cf0090136b52eb1e969e7', 'sha256:8c78ba22d913cea7771d87c7f439521b466c099ee5b2225ca577958df4d8e11b', 'sha256:b107a8ee81dbd48e81b8d53ffc72cb9adf2f3a085db841718b0a2479a73d7524', 'sha256:61c91fb75c811bc52485575aff0f1cf85cad3b815aa75d42288350834575d60b', '1c9a53a5f918e1edab53f58f449bca639377e3ebe791e9be4dc7a7fe42c01574', '5efc208e3408e7cf4f712be6f6de5942755dcb367d17d459ff93d12156ac8073', '694d8f696a95c3bc032d146f5a73e4d1fb90536c888cf0090136b52eb1e969e7', '8c78ba22d913cea7771d87c7f439521b466c099ee5b2225ca577958df4d8e11b', 'b107a8ee81dbd48e81b8d53ffc72cb9adf2f3a085db841718b0a2479a73d7524', '61c91fb75c811bc52485575aff0f1cf85cad3b815aa75d42288350834575d60b');\n"
        "DELETE FROM patch_health WHERE fingerprint IN ('sha256:1c9a53a5f918e1edab53f58f449bca639377e3ebe791e9be4dc7a7fe42c01574', 'sha256:5efc208e3408e7cf4f712be6f6de5942755dcb367d17d459ff93d12156ac8073', 'sha256:694d8f696a95c3bc032d146f5a73e4d1fb90536c888cf0090136b52eb1e969e7', 'sha256:8c78ba22d913cea7771d87c7f439521b466c099ee5b2225ca577958df4d8e11b', 'sha256:b107a8ee81dbd48e81b8d53ffc72cb9adf2f3a085db841718b0a2479a73d7524', 'sha256:61c91fb75c811bc52485575aff0f1cf85cad3b815aa75d42288350834575d60b', '1c9a53a5f918e1edab53f58f449bca639377e3ebe791e9be4dc7a7fe42c01574', '5efc208e3408e7cf4f712be6f6de5942755dcb367d17d459ff93d12156ac8073', '694d8f696a95c3bc032d146f5a73e4d1fb90536c888cf0090136b52eb1e969e7', '8c78ba22d913cea7771d87c7f439521b466c099ee5b2225ca577958df4d8e11b', 'b107a8ee81dbd48e81b8d53ffc72cb9adf2f3a085db841718b0a2479a73d7524', '61c91fb75c811bc52485575aff0f1cf85cad3b815aa75d42288350834575d60b');\n"
    )
    tmp_path = "temp_purge_bleed.sql"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(purge_sql)
        run_res = _run_wrangler_d1([f"--file={tmp_path}"])
        if run_res.returncode == 0:
            print("Successfully purged bleed and synthetic rows from remote D1.")
        else:
            print(f"Purge notice: {run_res.stderr}", file=sys.stderr)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def migrate_simhash_columns() -> None:
    for col in ["simhash_b0", "simhash_b1", "simhash_b2", "simhash_b3"]:
        res = _run_wrangler_d1(["--command", f"ALTER TABLE grievances ADD COLUMN {col} INTEGER"])
        if res.returncode == 0:
            print(f"Successfully added column {col} to grievances.")
        else:
            print(f"Notice adding {col}: {res.stderr.strip()}", file=sys.stderr)


def _query_d1_rest(sql: str, token: str, account_id: str) -> List[Dict[str, Any]]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{D1_DATABASE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-D1-Migrator/2.1",
    }
    req = urllib.request.Request(url, data=json.dumps({"sql": sql}).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        if not data.get("success"):
            raise RuntimeError(f"D1 REST query failed: {data.get('errors')}")
        result = data.get("result") or []
        return result[0].get("results", []) if result else []


def backfill_simhash_bands(
    batch_size: int = 250,
    max_batches: int = 200,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Idempotent chunked SimHash backfill strictly for PROMOTED grievances with NULL simhash_b0.
    Uses D1 REST API when token is available; falls back to Windows-safe wrangler CLI.
    Never modifies DEAD_LETTER_QUARANTINE rows.
    """
    from fmagenticl.client.simhash import compute_grievance_simhash_bands

    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN") or ""
    if not token:
        try:
            sys.path.insert(0, str(REPO_ROOT / "scripts"))
            from fetch_cf_analytics import resolve_token
            token = resolve_token()
        except Exception:
            token = ""
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID") or os.environ.get("CF_ACCOUNT_ID") or DEFAULT_ACCOUNT_ID

    total_updated = 0
    batches_run = 0
    remaining_sample = None

    for _ in range(max_batches):
        select_sql = (
            f"SELECT id, symptom FROM grievances "
            f"WHERE simhash_b0 IS NULL AND queue_status = 'PROMOTED' LIMIT {int(batch_size)};"
        )
        if token:
            rows = _query_d1_rest(select_sql, token, account_id)
        else:
            res = _run_wrangler_d1(["--json", "--command", select_sql])
            if res.returncode != 0:
                raise RuntimeError(f"Wrangler D1 select failed: {res.stderr}")
            parsed = _extract_wrangler_json(res.stdout or "")
            rows = parsed[0].get("results", []) if isinstance(parsed, list) and parsed else []

        if not rows:
            remaining_sample = 0
            break

        batches_run += 1
        stmts = []
        for row in rows:
            gid = str(row["id"]).replace("'", "''")
            b0, b1, b2, b3 = compute_grievance_simhash_bands(str(row.get("symptom") or ""))
            stmts.append(
                f"UPDATE grievances SET simhash_b0={b0}, simhash_b1={b1}, simhash_b2={b2}, simhash_b3={b3} "
                f"WHERE id='{gid}' AND simhash_b0 IS NULL;"
            )

        if dry_run:
            total_updated += len(stmts)
            remaining_sample = len(rows)
            print(f"[DRY-RUN] Batch {batches_run}: prepared {len(stmts)} SimHash UPDATE statements (0 written).")
            break

        if token:
            for i in range(0, len(stmts), 50):
                _query_d1_rest("\n".join(stmts[i : i + 50]), token, account_id)
        else:
            tmp_sql = "temp_backfill_simhash.sql"
            try:
                Path(tmp_sql).write_text("\n".join(stmts), encoding="utf-8")
                res = _run_wrangler_d1([f"--file={tmp_sql}"])
                if res.returncode != 0:
                    raise RuntimeError(f"Wrangler D1 update failed: {res.stderr}")
            finally:
                if os.path.exists(tmp_sql):
                    os.remove(tmp_sql)

        total_updated += len(stmts)
        print(f"[+] SimHash backfill batch {batches_run}: updated {len(stmts)} rows (total={total_updated}).")

    return {"batches": batches_run, "updated": total_updated, "remaining_sample": remaining_sample, "dry_run": dry_run}


def main() -> None:
    parser = argparse.ArgumentParser(description="FMagenticL D1 migrations and chunked SimHash backfill")
    parser.add_argument("--backfill-simhash", action="store_true", help="Populate simhash_b0..b3 on PROMOTED rows where NULL")
    parser.add_argument("--batch-size", type=int, default=250, help="Rows per SELECT batch (default: 250)")
    parser.add_argument("--max-batches", type=int, default=200, help="Max batches per invocation (default: 200)")
    parser.add_argument("--dry-run", action="store_true", help="Inspect batch count without writing D1 UPDATEs")
    args = parser.parse_args()

    if args.backfill_simhash:
        summary = backfill_simhash_bands(
            batch_size=args.batch_size,
            max_batches=args.max_batches,
            dry_run=args.dry_run,
        )
        print("SIMHASH_BACKFILL_SUMMARY:", json.dumps(summary))
        return

    migrate_simhash_columns()
    migrate_if_needed()
    purge_bleed_and_synthetic_rows()
    normalize_model_attributions()


if __name__ == "__main__":
    main()
