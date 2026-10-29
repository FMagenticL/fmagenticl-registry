import os
import sys
import json
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.fetch_cf_analytics import resolve_token, D1_DATABASE_ID

ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "f83dbbaa261d9ceac1f9f666fa9bd07b"

TEST_GRIEVANCE_IDS = [
    '094aec15-63c4-469e-8422-124e9eb03178',
    '14b1f92a-cc4d-44ab-9f25-ebaf08d8c4d8',
    '8c1e4247-ee5d-4bc4-b6d4-339887936e18',
    'f1424bde-44f9-4b53-9020-2c845bdf5d4c',
    'b6e8b3d5-db2a-4900-a242-efed4078a6fa',
    'd8b70e1a-4bd4-4379-98b7-c2be0b47ec51',
    'b325b8e7-1800-4d29-96df-23414e176066'
]

TEST_FINGERPRINTS = [
    '0000000000000000000000000000000000000000000000000000000000000002',
    '9e077ff76a724dffa86e892750ed52f543cfead41d4c447d8776512c30d7b78e',
    '76d1558c6e4f44caba56110a75dcb76667e86bc39db74401abfe43df45ddcdf9'
]

def execute_d1_sql(token: str, sql: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{D1_DATABASE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-Purge-Canary/1.0"
    }
    payload = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    token = resolve_token()
    if not token:
        print("ERROR: Could not resolve Cloudflare API token", file=sys.stderr)
        sys.exit(1)

    print("Executing purge of Phase 11.0 test artifacts in D1...")
    
    # 1. Purge grievances
    in_ids = ", ".join(f"'{gid}'" for gid in TEST_GRIEVANCE_IDS)
    purge_g_sql = f"DELETE FROM grievances WHERE id IN ({in_ids});"
    res_g = execute_d1_sql(token, purge_g_sql)
    print(f"  * Purged test grievances: {res_g.get('success')}")

    # 2. Purge patch_health
    in_fps = ", ".join(f"'{fp}'" for fp in TEST_FINGERPRINTS)
    purge_ph_sql = f"DELETE FROM patch_health WHERE fingerprint IN ({in_fps});"
    res_ph = execute_d1_sql(token, purge_ph_sql)
    print(f"  * Purged test patch_health: {res_ph.get('success')}")

    # 3. Purge rate_limits
    purge_rl_sql = "DELETE FROM rate_limits WHERE submitted_by LIKE 'outcome:208.168.238.33:%';"
    res_rl = execute_d1_sql(token, purge_rl_sql)
    print(f"  * Purged test rate_limits: {res_rl.get('success')}")

    # Post-purge Census
    print("\n--- POST-PURGE D1 CENSUS ---")
    census_g = execute_d1_sql(token, "SELECT queue_status, verification_tier, COUNT(*) as cnt FROM grievances GROUP BY queue_status, verification_tier;")
    print("Grievances:")
    for row in census_g.get("result", [{}])[0].get("results", []):
        print(f"  {row.get('queue_status')} | {row.get('verification_tier')}: {row.get('cnt')}")

    census_ph = execute_d1_sql(token, "SELECT status, COUNT(*) as cnt FROM patch_health GROUP BY status;")
    print("Patch Health:")
    for row in census_ph.get("result", [{}])[0].get("results", []):
        print(f"  {row.get('status')}: {row.get('cnt')}")

    census_rl = execute_d1_sql(token, "SELECT COUNT(*) as cnt FROM rate_limits WHERE submitted_by LIKE 'outcome:%';")
    print(f"Remaining outcome rate limits: {census_rl.get('result', [{}])[0].get('results', [{}])[0].get('cnt')}")

if __name__ == "__main__":
    main()
