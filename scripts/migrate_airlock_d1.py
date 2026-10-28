import os
import sys
import json
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.fetch_cf_analytics import resolve_token

D1_DATABASE_ID = "8f0f1fae-2d36-4361-a547-26c0aa08d23d"
ACCOUNT_ID = (
    os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    or os.environ.get("CF_ACCOUNT_ID")
    or "f83dbbaa261d9ceac1f9f666fa9bd07b"
)


def execute_d1_sql(account_id: str, token: str, sql: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{D1_DATABASE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-Airlock-Migrator/1.0",
    }
    payload = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_census(account_id: str, token: str, label: str):
    print(f"\n=== CENSUS: {label} ===")
    g_res = execute_d1_sql(
        account_id,
        token,
        "SELECT queue_status, verification_tier, COUNT(*) as cnt FROM grievances GROUP BY queue_status, verification_tier ORDER BY queue_status, cnt DESC;",
    )
    print("Grievances Distribution:")
    for row in g_res.get("result", [{}])[0].get("results", []):
        print(f"  queue_status: {row.get('queue_status')} | verification_tier: {row.get('verification_tier')} | count: {row.get('cnt')}")

    t_res = execute_d1_sql(
        account_id,
        token,
        "SELECT queue_status, verification_tier, COUNT(*) as cnt FROM telemetry GROUP BY queue_status, verification_tier ORDER BY queue_status, cnt DESC;",
    )
    print("Telemetry Distribution:")
    for row in t_res.get("result", [{}])[0].get("results", []):
        print(f"  queue_status: {row.get('queue_status')} | verification_tier: {row.get('verification_tier')} | count: {row.get('cnt')}")


def main():
    token = resolve_token()
    if not token:
        print("ERROR: Could not resolve Cloudflare API token.", file=sys.stderr)
        sys.exit(1)

    print(f"Connected to Cloudflare D1: {D1_DATABASE_ID}")
    run_census(ACCOUNT_ID, token, "BEFORE MIGRATION")

    print("\nExecuting Migration Statements...")
    migration_sql = """
    UPDATE grievances SET queue_status = 'PROMOTED' WHERE queue_status = 'committed';
    UPDATE telemetry SET queue_status = 'PROMOTED' WHERE queue_status = 'committed';
    """
    res = execute_d1_sql(ACCOUNT_ID, token, migration_sql)
    for idx, r in enumerate(res.get("result", [])):
        print(f"  Query {idx + 1} rows changed: {r.get('meta', {}).get('changes', 0)}")

    run_census(ACCOUNT_ID, token, "AFTER MIGRATION")
    print("\nMigration completed successfully.")


if __name__ == "__main__":
    main()
