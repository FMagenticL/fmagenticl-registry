#!/usr/bin/env python3
"""
FMagenticL - Automated Cloudflare Analytics & D1 Telemetry Fetcher (Honest Accounting + Bucket A/B/C Split)
Queries the Cloudflare GraphQL API (httpRequestsAdaptiveGroups) for:
  1. Historical Window: 2026-10-23T00:00:00Z to now
  2. Recent Window: now-4h to now
Extracts total requests, bandwidth, status codes (2xx, 3xx, 4xx, 5xx server/gateway errors),
explicit 504 timeouts (tracked as 5xx subtype, never subtracted or masked), Bucket A/B/C path-segregated
5xx accounting (/mcp runtime vs. core static CDN vs. scanner noise), and live D1 database counts.
"""

import os
import sys
import json
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DAILY_LOG_PATH = REPO_ROOT / "daily_telemetry.md"
GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"
D1_DATABASE_ID = "8f0f1fae-2d36-4361-a547-26c0aa08d23d"

STATIC_V1_PATHS = {"/v1/health", "/v1/snapshot.json", "/v1/snapshot.sig"}
CORE_STATIC_EXACT = {
    "/", "/v1/health", "/v1/snapshot.json", "/v1/snapshot.sig",
    "/workarounds.json", "/registry.json", "/guestbook.json",
    "/llms.txt", "/llms-full.txt", "/robots.txt", "/favicon.ico", "/openapi.json",
}


def classify_error_path(path: str) -> str:
    """
    Classify request path into:
      - 'bucket_a_runtime': /mcp, /mcp/*, dynamic /v1/*, /health, /api/v1/patches
      - 'bucket_b_static': core static CDN files, /shards/*, /.well-known/*
      - 'bucket_c_scanner': unmapped scanner / bot probes (e.g. /a131c452..., /sw.js)
    """
    p = (path or "/").rstrip("/") or "/"
    if (
        p in ("/mcp", "/mcp/server-card", "/health", "/api/v1/patches")
        or p.startswith("/mcp/")
        or (p.startswith("/v1/") and p not in STATIC_V1_PATHS)
    ):
        return "bucket_a_runtime"
    if (
        p in CORE_STATIC_EXACT
        or (p.startswith("/shards/") and p != "/shards/workarounds/fastapi.json")
        or p.startswith("/.well-known/")
    ):
        return "bucket_b_static"
    return "bucket_c_scanner"


def resolve_token() -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    if token:
        return token.strip()

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


def build_slice_query(account_tag: str, start_iso: str, end_iso: str) -> str:
    return f"""
query {{
  viewer {{
    accounts(filter: {{ accountTag: "{account_tag}" }}) {{
      totals: httpRequestsAdaptiveGroups(
        limit: 1
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_leq: "{end_iso}"
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
          datetime_leq: "{end_iso}"
        }}
        orderBy: [count_DESC]
      ) {{
        count
        dimensions {{
          edgeResponseStatus
          originResponseStatus
        }}
      }}
      paths: httpRequestsAdaptiveGroups(
        limit: 50
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_leq: "{end_iso}"
        }}
        orderBy: [count_DESC]
      ) {{
        count
        dimensions {{
          clientRequestPath
        }}
      }}
      errorsByPath: httpRequestsAdaptiveGroups(
        limit: 100
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_leq: "{end_iso}"
          edgeResponseStatus_geq: 500
          edgeResponseStatus_lt: 600
        }}
        orderBy: [count_DESC]
      ) {{
        count
        dimensions {{
          clientRequestPath
          edgeResponseStatus
        }}
      }}
      countries: httpRequestsAdaptiveGroups(
        limit: 25
        filter: {{
          datetime_geq: "{start_iso}"
          datetime_leq: "{end_iso}"
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
        "User-Agent": "FMagenticL-Analytics-Fetcher/1.4",
    }
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(GRAPHQL_ENDPOINT, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return json.loads(err_body)
        except Exception:
            return {"errors": [{"message": f"HTTP {e.code}: {err_body}"}]}
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


def fetch_window_metrics(account_id: str, start_dt: datetime, end_dt: datetime, token: str) -> dict:
    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    res = execute_graphql(build_slice_query(account_id, start_iso, end_iso), token)
    errors = res.get("errors")

    slices_data = []
    if not errors:
        slices_data.append(res)
    else:
        cur = start_dt
        while cur < end_dt:
            nxt = min(cur + timedelta(hours=24), end_dt)
            s_iso = cur.strftime("%Y-%m-%dT%H:%M:%SZ")
            e_iso = nxt.strftime("%Y-%m-%dT%H:%M:%SZ")
            s_res = execute_graphql(build_slice_query(account_id, s_iso, e_iso), token)
            if s_res.get("errors"):
                raise RuntimeError(f"GraphQL error for slice {s_iso}..{e_iso}: {s_res['errors']}")
            slices_data.append(s_res)
            cur = nxt

    total_requests = 0
    total_bytes = 0
    c_2xx = 0
    c_3xx = 0
    c_4xx = 0
    c_5xx_total = 0
    c_504 = 0
    c_5xx_other = 0
    path_counts = Counter()
    error_path_counts = Counter()
    country_counts = Counter()

    mcp_504 = 0
    mcp_5xx_crash = 0
    bucket_a_504 = 0
    bucket_a_5xx_crash = 0
    bucket_b_5xx = 0
    bucket_c_scanner_5xx = 0
    bucket_a_error_paths = Counter()
    bucket_b_error_paths = Counter()

    for s_res in slices_data:
        accounts = s_res.get("data", {}).get("viewer", {}).get("accounts", [])
        if not accounts:
            continue
        acc = accounts[0]

        totals_list = acc.get("totals", [])
        if totals_list:
            total_requests += totals_list[0].get("count", 0) or 0
            t_sum = totals_list[0].get("sum", {}) or {}
            total_bytes += t_sum.get("edgeResponseBytes", 0) or 0

        for item in acc.get("statusCodes", []):
            dims = item.get("dimensions", {}) or {}
            status = dims.get("edgeResponseStatus", 0)
            reqs = item.get("count", 0) or 0
            if 200 <= status < 300:
                c_2xx += reqs
            elif 300 <= status < 400:
                c_3xx += reqs
            elif 400 <= status < 500:
                c_4xx += reqs
            elif 500 <= status < 600:
                c_5xx_total += reqs
                if status == 504:
                    c_504 += reqs
                else:
                    c_5xx_other += reqs

        for item in acc.get("paths", []):
            dims = item.get("dimensions", {}) or {}
            path = dims.get("clientRequestPath") or "/"
            reqs = item.get("count", 0) or 0
            path_counts[path] += reqs

        for item in acc.get("errorsByPath", []):
            dims = item.get("dimensions", {}) or {}
            path = dims.get("clientRequestPath") or "/"
            code = dims.get("edgeResponseStatus", 500)
            reqs = item.get("count", 0) or 0
            label = f"{path} ({code})"
            error_path_counts[label] += reqs

            bucket = classify_error_path(path)
            if bucket == "bucket_a_runtime":
                bucket_a_error_paths[label] += reqs
                if code == 504:
                    bucket_a_504 += reqs
                else:
                    bucket_a_5xx_crash += reqs
                if path == "/mcp" or path.startswith("/mcp/"):
                    if code == 504:
                        mcp_504 += reqs
                    else:
                        mcp_5xx_crash += reqs
            elif bucket == "bucket_b_static":
                bucket_b_5xx += reqs
                bucket_b_error_paths[label] += reqs
            else:
                bucket_c_scanner_5xx += reqs

        for item in acc.get("countries", []):
            dims = item.get("dimensions", {}) or {}
            country = dims.get("clientCountryName") or "Unknown"
            reqs = item.get("count", 0) or 0
            country_counts[country] += reqs

    rate_5xx = (c_5xx_total / total_requests * 100) if total_requests > 0 else 0.0
    mcp_requests = path_counts.get("/mcp", 0) + sum(
        v for k, v in path_counts.items() if k.startswith("/mcp/")
    )
    mcp_5xx_total = mcp_504 + mcp_5xx_crash
    mcp_5xx_rate = (mcp_5xx_total / mcp_requests * 100.0) if mcp_requests > 0 else 0.0

    return {
        "start_iso": start_iso,
        "end_iso": end_iso,
        "total_requests": total_requests,
        "bandwidth_mb": total_bytes / (1024 * 1024),
        "c_2xx": c_2xx,
        "c_3xx": c_3xx,
        "c_4xx": c_4xx,
        "c_5xx_total": c_5xx_total,
        "c_504": c_504,
        "c_5xx_other": c_5xx_other,
        "rate_5xx": rate_5xx,
        "mcp_requests": mcp_requests,
        "mcp_504": mcp_504,
        "mcp_5xx_crash": mcp_5xx_crash,
        "mcp_5xx_total": mcp_5xx_total,
        "mcp_5xx_rate": mcp_5xx_rate,
        "bucket_a_504": bucket_a_504,
        "bucket_a_5xx_crash": bucket_a_5xx_crash,
        "bucket_a_error_paths": bucket_a_error_paths.most_common(5),
        "bucket_b_5xx": bucket_b_5xx,
        "bucket_b_error_paths": bucket_b_error_paths.most_common(5),
        "bucket_c_scanner_5xx": bucket_c_scanner_5xx,
        "top_paths": path_counts.most_common(10),
        "top_error_paths": error_path_counts.most_common(5),
        "top_countries": country_counts.most_common(5),
    }


def query_d1_count(account_id: str, token: str, sql: str) -> tuple[int, str | None]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{D1_DATABASE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-Analytics-Fetcher/1.4",
    }
    payload = json.dumps({"sql": sql}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("result", [{}])[0].get("results", [])
            if results:
                return int(list(results[0].values())[0]), None
            return 0, None
    except Exception as e:
        return 0, str(e)


def fetch_d1_state(account_id: str, token: str) -> dict:
    telemetry_cnt, t_err = query_d1_count(account_id, token, "SELECT COUNT(*) FROM telemetry;")
    grievances_cnt, g_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE queue_status = 'PROMOTED';"
    )
    verified_wa_cnt, vw_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE queue_status = 'PROMOTED' "
        "AND verification_tier IN ('verified_merged_pr', 'reporter_verified', 'internal_forensic_verified', 'cryptographic_proof') "
        "AND submitted_by NOT IN ('harvester-v1', 'osv-harvester');"
    )
    bot_grv_cnt, bg_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE queue_status = 'PROMOTED' "
        "AND (verification_tier = 'osv_verified' OR submitted_by IN ('harvester-v1', 'osv-harvester'));"
    )
    pre2026_osv_cnt, p26_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE verification_tier = 'osv_verified' AND created_at < '2026-01-01';"
    )
    quarantined_grv_cnt, qg_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE queue_status = 'DEAD_LETTER_QUARANTINE';"
    )
    quarantined_tel_cnt, qt_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM telemetry WHERE queue_status = 'DEAD_LETTER_QUARANTINE';"
    )
    auto_quarantined_cnt, aq_err = query_d1_count(
        account_id, token,
        "SELECT COUNT(*) FROM grievances WHERE queue_status = 'AUTO_QUARANTINED_BY_SENTRY';"
    )
    visits_cnt, v_err = query_d1_count(account_id, token, "SELECT COUNT(DISTINCT model) FROM visits;")

    errs = [e for e in (t_err, g_err, vw_err, bg_err, p26_err, qg_err, qt_err, aq_err, v_err) if e]

    compiled_patches = 85
    try:
        reg_path = REPO_ROOT / "dist" / "registry.json"
        if reg_path.exists():
            reg_data = json.loads(reg_path.read_text(encoding="utf-8"))
            compiled_patches = reg_data.get("count", len(reg_data.get("patches", [])))
    except Exception:
        pass

    total_quarantined = quarantined_grv_cnt + quarantined_tel_cnt + auto_quarantined_cnt

    return {
        "telemetry": telemetry_cnt,
        "compiled_patches": compiled_patches,
        "grievances": grievances_cnt,
        "verified_workarounds": verified_wa_cnt,
        "bot_harvested_grievances": bot_grv_cnt,
        "pre2026_osv_leaks": pre2026_osv_cnt,
        "quarantined": total_quarantined,
        "quarantined_telemetry": quarantined_tel_cnt,
        "quarantined_grievances": quarantined_grv_cnt,
        "auto_quarantined_sentry": auto_quarantined_cnt,
        "visits": visits_cnt,
        "error": "; ".join(errs) if errs else None,
    }


def format_paths(top_paths: list) -> str:
    if not top_paths:
        return "None"
    return ", ".join(f"`{p}` ({c:,})" for p, c in top_paths)


def format_countries(top_countries: list) -> str:
    if not top_countries:
        return "None"
    return ", ".join(f"{c} ({n:,})" for c, n in top_countries)


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
            "ERROR: CLOUDFLARE_API_TOKEN is not set in the environment, and cf.pdf was not found.",
            file=sys.stderr,
        )
        sys.exit(1)

    now = datetime.now(timezone.utc)
    hist_start = datetime(2026, 10, 23, 0, 0, 0, tzinfo=timezone.utc)
    recent_start = now - timedelta(hours=4)

    hist = fetch_window_metrics(account_id, hist_start, now, token)
    recent = fetch_window_metrics(account_id, recent_start, now, token)
    d1 = fetch_d1_state(account_id, token)

    d1_status_str = (
        f"{d1['telemetry']} Telemetry Submissions ({d1['compiled_patches']} Compiled Patches), "
        f"{d1['grievances']} Promoted Grievances (71-Truth Split: {d1.get('verified_workarounds', 71)} Verified Workarounds + "
        f"{d1.get('bot_harvested_grievances', 0)} Bot-Harvested), "
        f"{d1.get('quarantined', 0)} Quarantined (Tel: {d1.get('quarantined_telemetry', 0)}, Grv: {d1.get('quarantined_grievances', 0)}, Auto: {d1.get('auto_quarantined_sentry', 0)}), "
        f"{d1.get('pre2026_osv_leaks', 0)} Pre-2026 OSV Leaks, "
        f"{d1['visits']} Unique Models (visits)"
        if not d1["error"]
        else f"⚠️ D1 QUERY FAILED: {d1['error']}"
    )

    hist_err_str = format_paths(hist["top_error_paths"])
    recent_err_str = format_paths(recent["top_error_paths"])

    report_markdown = (
        f"### 📊 CUMULATIVE ANALYTICS (Oct 23 – Now) [Sampled Estimates]\n"
        f"- **Total Requests:** {hist['total_requests']:,}\n"
        f"- **Total Bandwidth:** {hist['bandwidth_mb']:.2f} MB\n"
        f"- **Status Codes:** 2xx: {hist['c_2xx']:,} | 3xx: {hist['c_3xx']:,} | 4xx: {hist['c_4xx']:,} | 5xx (All Server/Gateway Errors): {hist['c_5xx_total']:,} (of which 504 Timeouts: {hist['c_504']:,}, Other 5xx: {hist['c_5xx_other']:,})\n"
        f"- **5xx Error Rate:** {hist['rate_5xx']:.2f}% (Bucket A `/mcp`+Runtime: {hist['bucket_a_504'] + hist['bucket_a_5xx_crash']} | Bucket B Static CDN: {hist['bucket_b_5xx']} | Bucket C Scanner Probes: {hist['bucket_c_scanner_5xx']})\n"
        f"- **Top 5xx Error Paths:** [{hist_err_str}]\n"
        f"- **Top Paths:** [{format_paths(hist['top_paths'])}]\n"
        f"- **Top Countries:** [{format_countries(hist['top_countries'])}]\n"
        f"- **D1 Database State:** {d1_status_str}\n\n"
        f"### ⚡ LAST 4 HOURS (Recent Window) [Sampled Estimates]\n"
        f"- **Total Requests:** {recent['total_requests']:,} (`/mcp` Requests: {recent['mcp_requests']:,})\n"
        f"- **Status Codes:** 2xx: {recent['c_2xx']:,} | 3xx: {recent['c_3xx']:,} | 4xx: {recent['c_4xx']:,} | 5xx (All Server/Gateway Errors): {recent['c_5xx_total']:,} (of which 504 Timeouts: {recent['c_504']:,}, Other 5xx: {recent['c_5xx_other']:,})\n"
        f"- **5xx Bucket Split (4h):** Bucket A (`/mcp`+Runtime): {recent['bucket_a_504']} 504s + {recent['bucket_a_5xx_crash']} crashes (`/mcp` 5xx rate: {recent['mcp_5xx_rate']:.2f}%) | Bucket B (Core Static CDN): {recent['bucket_b_5xx']} | Bucket C (Scanner Noise): {recent['bucket_c_scanner_5xx']}\n"
        f"- **Top 5xx Error Paths:** [{recent_err_str}]\n"
        f"- **Top Paths:** [{format_paths(recent['top_paths'])}]\n"
    )

    print(report_markdown.strip())

    summary_path = REPO_ROOT / "scratch" / "cf_latest_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": now.isoformat(),
            "hist": hist,
            "recent": recent,
            "d1": d1,
        }, f, indent=2)

    timestamp_header = f"\n\n## 🕒 Sentry Diagnostic Run — {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
    with open(DAILY_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(timestamp_header + report_markdown + "\n---\n")


if __name__ == "__main__":
    main()
