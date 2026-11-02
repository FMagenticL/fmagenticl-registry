#!/usr/bin/env python3
"""
FMagenticL - Automated Cloudflare Daily Analytics Archiver
Preserves 24-hour raw GraphQL telemetry snapshots permanently on disk
before Cloudflare's strict 30-day retention window expires (launch data Nov 22 cliff).

Usage:
    python scripts/archive_cf_analytics.py [--date YYYY-MM-DD] [--all-available]
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from fetch_cf_analytics import resolve_token, execute_graphql

ARCHIVE_DIR = REPO_ROOT / "data" / "analytics_archive"
ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID") or os.environ.get("CF_ACCOUNT_ID") or "f83dbbaa261d9ceac1f9f666fa9bd07b"


def archive_day(account_id: str, date_str: str, token: str) -> bool:
    target_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    start_iso = target_date.strftime("%Y-%m-%dT00:00:00Z")
    end_iso = (target_date + timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")

    out_file = ARCHIVE_DIR / f"analytics_{date_str}.json"
    if out_file.exists():
        print(f"[*] Archive for {date_str} already exists ({out_file.stat().st_size:,} bytes). Skipping.")
        return True

    print(f"[*] Pulling Cloudflare GraphQL analytics for {date_str} ({start_iso} .. {end_iso})...")
    query = f"""
    query {{
      viewer {{
        accounts(filter: {{ accountTag: "{account_id}" }}) {{
          totals: httpRequestsAdaptiveGroups(
            limit: 1
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}" }}
          ) {{
            count
            sum {{ edgeResponseBytes visits }}
          }}
          statusCodes: httpRequestsAdaptiveGroups(
            limit: 100
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}" }}
            orderBy: [count_DESC]
          ) {{
            count
            dimensions {{ edgeResponseStatus originResponseStatus }}
          }}
          paths: httpRequestsAdaptiveGroups(
            limit: 100
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}" }}
            orderBy: [count_DESC]
          ) {{
            count
            dimensions {{ clientRequestPath }}
          }}
          errorsByPath: httpRequestsAdaptiveGroups(
            limit: 50
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}", edgeResponseStatus_geq: 500 }}
            orderBy: [count_DESC]
          ) {{
            count
            dimensions {{ clientRequestPath edgeResponseStatus }}
          }}
          countries: httpRequestsAdaptiveGroups(
            limit: 50
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}" }}
            orderBy: [count_DESC]
          ) {{
            count
            dimensions {{ clientCountryName }}
          }}
          hourly: httpRequestsAdaptiveGroups(
            limit: 100
            filter: {{ datetime_geq: "{start_iso}", datetime_lt: "{end_iso}" }}
            orderBy: [datetimeHour_ASC]
          ) {{
            count
            sum {{ edgeResponseBytes }}
            dimensions {{ datetimeHour }}
          }}
        }}
      }}
    }}
    """
    res = execute_graphql(query, token)
    if res.get("errors"):
        print(f"[-] GraphQL error for {date_str}: {res['errors']}")
        return False

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "date": date_str,
        "archived_at_utc": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "data": res.get("data", {}).get("viewer", {}).get("accounts", [{}])[0]
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] Successfully archived {date_str} to {out_file} ({out_file.stat().st_size:,} bytes).")
    return True


def main():
    parser = argparse.ArgumentParser(description="Archive daily Cloudflare GraphQL analytics.")
    parser.add_argument("--date", help="Specific date YYYY-MM-DD to archive.")
    parser.add_argument("--all-available", action="store_true", help="Archive all dates from Oct 23 to yesterday.")
    args = parser.parse_args()

    token = resolve_token()
    if not token:
        print("[-] CLOUDFLARE_API_TOKEN is required.", file=sys.stderr)
        sys.exit(1)

    if args.date:
        archive_day(ACCOUNT_ID, args.date, token)
    elif args.all_available:
        cur = datetime(2026, 10, 23, tzinfo=timezone.utc)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        while cur <= yesterday:
            archive_day(ACCOUNT_ID, cur.strftime("%Y-%m-%d"), token)
            cur += timedelta(days=1)
    else:
        # Default to yesterday
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        archive_day(ACCOUNT_ID, yesterday, token)


if __name__ == "__main__":
    main()
