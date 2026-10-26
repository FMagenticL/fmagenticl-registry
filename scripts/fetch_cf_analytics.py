#!/usr/bin/env python3
"""
FMagenticL - Automated Cloudflare Analytics Fetcher
Queries the Cloudflare GraphQL API for edge telemetry (requests, bandwidth,
status codes, geographic origin, and security/WAF blocks) over the last 24 hours.
"""

import os
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DAILY_LOG_PATH = REPO_ROOT / "daily_telemetry.md"
GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"


def resolve_token() -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    if token:
        return token.strip()

    # Automatic local fallback: read from Downloads/cf.pdf or Desktop/cf.pdf
    pdf_candidates = [
        Path.home() / "Downloads" / "cf.pdf",
        Path.home() / "Desktop" / "cf.pdf",
    ]
    for p in pdf_candidates:
        if p.exists():
            try:
                import pypdf
                reader = pypdf.PdfReader(str(p))
                txt = "".join(page.extract_text() or "" for page in reader.pages)
                clean = txt.strip().replace(" ", "").replace("\r", "").replace("\n", "")
                if clean.startswith("cfut_") or clean.startswith("cfat_"):
                    return clean
            except Exception:
                pass
    return ""


def build_query(account_tag: str, start_iso: str, end_iso: str) -> str:
    return f"""
query {{
  viewer {{
    accounts(filter: {{ accountTag: "{account_tag}" }}) {{
      totals: httpRequestsAdaptiveGroups(
        limit: 1
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_lt: "{end_iso}"
        }}
      ) {{
        count
        sum {{
          edgeResponseBytes
          visits
        }}
      }}
      statusCodes: httpRequestsAdaptiveGroups(
        limit: 100
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_lt: "{end_iso}"
        }}
        orderBy: [count_DESC]
      ) {{
        count
        dimensions {{
          edgeResponseStatus
        }}
      }}
      countries: httpRequestsAdaptiveGroups(
        limit: 5
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_lt: "{end_iso}"
        }}
        orderBy: [count_DESC]
      ) {{
        count
        dimensions {{
          clientCountryName
        }}
      }}
    }}
  }}
}}
"""


def execute_graphql(query: str, token: str) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-Analytics-Fetcher/1.0",
    }
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(GRAPHQL_ENDPOINT, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return json.loads(err_body)
        except Exception:
            return {"errors": [{"message": f"HTTP {e.code}: {err_body}"}]}
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


def format_report(data: dict, start_iso: str, end_iso: str) -> str:
    accounts = data.get("data", {}).get("viewer", {}).get("accounts", [])
    if not accounts:
        return "No analytics data returned for this account."

    account_data = accounts[0]
    totals_list = account_data.get("totals", [])
    status_list = account_data.get("statusCodes", [])
    country_list = account_data.get("countries", [])

    total_requests = 0
    total_bytes = 0
    if totals_list:
        total_requests = totals_list[0].get("count", 0) or 0
        t_sum = totals_list[0].get("sum", {}) or {}
        total_bytes = t_sum.get("edgeResponseBytes", 0) or 0

    bandwidth_mb = total_bytes / (1024 * 1024)

    c_2xx = 0
    c_3xx = 0
    c_4xx = 0
    c_5xx = 0
    waf_403 = 0

    for item in status_list:
        dims = item.get("dimensions", {}) or {}
        status = dims.get("edgeResponseStatus", 0)
        reqs = item.get("count", 0) or 0

        if 200 <= status < 300:
            c_2xx += reqs
        elif 300 <= status < 400:
            c_3xx += reqs
        elif 400 <= status < 500:
            c_4xx += reqs
            if status == 403:
                waf_403 += reqs
        elif 500 <= status < 600:
            c_5xx += reqs

    top_countries_str = "None"
    if country_list:
        parts = []
        for c in country_list:
            c_name = c.get("dimensions", {}).get("clientCountryName") or "Unknown"
            c_reqs = c.get("count", 0) or 0
            parts.append(f"{c_name} ({c_reqs:,})")
        top_countries_str = ", ".join(parts) if parts else "None"

    report = (
        f"### 📊 FMagenticL Edge Telemetry (Last 24h)\n"
        f"- **Window:** {start_iso} to {end_iso}\n"
        f"- **Total Requests:** {total_requests:,}\n"
        f"- **Total Bandwidth:** {bandwidth_mb:.2f} MB\n"
        f"- **Status Codes:** 2xx: {c_2xx:,} | 4xx: {c_4xx:,} | 5xx: {c_5xx:,}\n"
        f"- **Top Countries:** {top_countries_str}\n"
        f"- **WAF Blocks (403s):** {waf_403:,}\n"
    )
    return report


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    token = resolve_token()
    account_id = (
        os.environ.get("CLOUDFLARE_ACCOUNT_ID")
        or os.environ.get("CF_ACCOUNT_ID")
        or "f83dbbaa261d9ceac1f9f666fa9bd07b"
    )

    if not token:
        print(
            "ERROR: CLOUDFLARE_API_TOKEN is not set in the environment, and cf.pdf was not found in Downloads or Desktop.\n\n"
            "To set it in PowerShell:\n"
            '  $env:CLOUDFLARE_API_TOKEN = "your_token_here"\n'
            f'  $env:CLOUDFLARE_ACCOUNT_ID = "{account_id}"\n'
            "  python scripts/fetch_cf_analytics.py\n",
            file=sys.stderr,
        )
        sys.exit(1)

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    query = build_query(account_id, start_iso, end_iso)
    result = execute_graphql(query, token)

    errors = result.get("errors")
    if errors:
        print("ERROR: Cloudflare GraphQL API returned errors:", file=sys.stderr)
        print(json.dumps(errors, indent=2), file=sys.stderr)
        sys.exit(1)

    report_markdown = format_report(result, start_iso, end_iso)
    print(report_markdown)

    # Append to daily_telemetry.md
    timestamp_entry = f"## Telemetry Entry — {end_iso}\n\n{report_markdown}\n---\n\n"
    with open(DAILY_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(timestamp_entry)
    print(f"[*] Appended telemetry report to {DAILY_LOG_PATH}")


if __name__ == "__main__":
    sys.exit(main())
