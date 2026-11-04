#!/usr/bin/env python3
"""
FMagenticL - 90-Minute Standing Diagnostics, Analytics & Autonomous Self-Healing Engine (Sentry v3.0)
Runs:
  0. Sentry Cycle Liveness / Missed-Cycle Detection (gap > 100 min) & Upstream Bot Git Sync
  1. Live HTTP Edge Probing with TTFB (/v1/health, /guestbook.json, /workarounds.json,
     /.well-known/agent-card.json, /shards/workarounds/_recent.json, /shards/workarounds/pydantic.json)
     + Fast-404 Edge Shielding Verification (/api/query, /sw.js, /shards/workarounds/fastapi.json)
  2. Read-only MCP JSON-RPC Probes (tools/list, tools/call fmagenticl_resolve,
     tools/call fmagenticl_get_workarounds with 50-item cap & <200KB payload assertion)
  3. Smart Monotonic Workarounds Mutation & Content Gate Audit (0 pre-2026 OSV, 0 purged IDs,
     0 npm @scope/pkg@[REDACTED corruptions, 71 verified_workarounds attribution pin)
  4. Live vs Local State Reconciliation (with autonomous D1-to-static rebuild if needed)
  5. GitHub Actions CI/CD & Harvester Workflow Health Check (deploy.yml & harvest.yml)
  6. Daily Cloudflare Analytics Archive Verification (data/analytics_archive/)
  7. Cloudflare GraphQL Analytics, 3-Way D1 Attribution Census & Distinct Agent Node Audit
"""

import sys
import os
import re
import json
import time
import hashlib
import urllib.request
import urllib.error
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(r"C:\Users\itari\Desktop\Antigravity Projects\Agentic Introspection Agent\fmagenticl")
SCRATCH_DIR = REPO_ROOT / "scratch"
SCRIPTS_DIR = REPO_ROOT / "scripts"
BASE_URL = "https://fmagenticl-registry.pages.dev"
STATE_CACHE = SCRATCH_DIR / ".last_workarounds_state.json"
SHA256_CACHE = SCRATCH_DIR / ".last_workarounds_sha256"
DAILY_TELEMETRY = REPO_ROOT / "daily_telemetry.md"
GITHUB_RUNS_URL = "https://api.github.com/repos/FMagenticL/fmagenticl-registry/actions/runs?per_page=10"

NPM_CORRUPTION_RE = re.compile(r"@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+@\[REDACTED")


def sync_upstream_bot_commits() -> str:
    """Pull upstream [BOT] commits from origin/main using --autostash so local daily_telemetry.md edits never block sync."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        subprocess.run(
            ["git", "fetch", "origin", "main", "--quiet"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=20, env=env
        )
        rev = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/main"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10, env=env
        )
        behind = int((rev.stdout or "0").strip() or "0")
        if behind > 0:
            pull = subprocess.run(
                ["git", "pull", "--rebase", "--autostash", "origin", "main"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30, env=env
            )
            if pull.returncode == 0:
                return f"Auto-pulled {behind} upstream commit(s) from origin/main (with --autostash)."
            return f"Auto-pull warning: {pull.stderr.strip()[:120]}"
        return "Local branch is up to date with origin/main."
    except Exception as e:
        return f"Git sync check skipped: {e}"


def probe_live_endpoints():
    endpoints_200 = [
        "/v1/health",
        "/guestbook.json",
        "/workarounds.json",
        "/.well-known/agent-card.json",
        "/shards/workarounds/_recent.json",
        "/shards/workarounds/pydantic.json",
    ]
    endpoints_404 = [
        "/api/query",
        "/sw.js",
        "/shards/workarounds/fastapi.json",
    ]
    results = {}
    for ep in endpoints_200:
        url = BASE_URL + ep
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-Sentry/3.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read()
                latency_ms = (time.perf_counter() - t0) * 1000.0
                results[ep] = {
                    "status": resp.getcode(),
                    "expected": 200,
                    "bytes": len(body),
                    "latency_ms": latency_ms,
                    "body": body,
                    "ok": resp.getcode() == 200 and len(body) > 0,
                }
        except urllib.error.HTTPError as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {"status": e.code, "expected": 200, "bytes": 0, "latency_ms": latency_ms, "ok": False}
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {"status": "ERROR", "expected": 200, "error": str(e), "latency_ms": latency_ms, "ok": False}

    for ep in endpoints_404:
        url = BASE_URL + ep
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-Sentry/3.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                latency_ms = (time.perf_counter() - t0) * 1000.0
                results[ep] = {"status": resp.getcode(), "expected": 404, "bytes": 0, "latency_ms": latency_ms, "ok": False}
        except urllib.error.HTTPError as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {
                "status": e.code,
                "expected": 404,
                "bytes": 0,
                "latency_ms": latency_ms,
                "ok": e.code == 404,
            }
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            results[ep] = {"status": "ERROR", "expected": 404, "error": str(e), "latency_ms": latency_ms, "ok": False}

    return results


def probe_mcp_protocol():
    url = BASE_URL + "/mcp"
    results = {}

    def post_mcp(req_id: int, method: str, params: dict | None = None):
        body_dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            body_dict["params"] = params
        payload = json.dumps(body_dict).encode("utf-8")
        t0 = time.perf_counter()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "FMagenticL-Sentry/3.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read()
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return resp.getcode(), raw, json.loads(raw.decode("utf-8")), latency_ms

    # 1. tools/list (must return 6 tools)
    try:
        code, raw, data, latency_ms = post_mcp(1, "tools/list")
        tools = data.get("result", {}).get("tools", [])
        results["tools/list"] = {
            "ok": code == 200 and len(tools) == 6,
            "tool_count": len(tools),
            "bytes": len(raw),
            "latency_ms": latency_ms,
        }
    except Exception as e:
        results["tools/list"] = {"ok": False, "error": str(e), "latency_ms": 0.0}

    # 2. tools/call fmagenticl_resolve
    try:
        code, raw, data, latency_ms = post_mcp(
            2, "tools/call", {"name": "fmagenticl_resolve", "arguments": {"target": "pydantic"}}
        )
        has_content = "result" in data and not data.get("error")
        results["tools/call:fmagenticl_resolve"] = {
            "ok": code == 200 and has_content,
            "bytes": len(raw),
            "latency_ms": latency_ms,
        }
    except Exception as e:
        results["tools/call:fmagenticl_resolve"] = {"ok": False, "error": str(e), "latency_ms": 0.0}

    # 3. tools/call fmagenticl_get_workarounds (must cap at <= 50 items and < 200 KB)
    try:
        code, raw, data, latency_ms = post_mcp(
            3, "tools/call", {"name": "fmagenticl_get_workarounds", "arguments": {}}
        )
        content_list = data.get("result", {}).get("content", [])
        inner = json.loads(content_list[0].get("text", "{}")) if content_list else {}
        items = inner.get("workarounds", [])
        truncated = inner.get("truncated")
        full_feed_url = inner.get("full_feed_url", "")
        ok = (
            code == 200
            and 0 < len(items) <= 50
            and truncated is True
            and full_feed_url.endswith("/workarounds.json")
            and len(raw) < 200_000
        )
        results["tools/call:fmagenticl_get_workarounds"] = {
            "ok": ok,
            "items_count": len(items),
            "truncated": truncated,
            "bytes": len(raw),
            "latency_ms": latency_ms,
        }
    except Exception as e:
        results["tools/call:fmagenticl_get_workarounds"] = {"ok": False, "error": str(e), "latency_ms": 0.0}

    return results


def load_purged_ids() -> set[str]:
    purged = {
        "grv_osv_PYSEC_2021_47", "grv_osv_GHSA_5jqp_qgf6_3pvh", "grv_osv_GHSA_8h2j_cgx8_6xv7",
        "grv_osv_GHSA_8c93_4hch_xgxp", "grv_osv_GHSA_8h5w_f6q9_wg35", "grv_osv_GHSA_cfph_4qqh_w828",
        "grv_osv_GHSA_f8mp_x433_5wpf", "grv_osv_PYSEC_2024_38", "grv_osv_GHSA_mr82_8j83_vxmv",
        "grv_osv_GHSA_3hjh_jh2h_vrg6", "grv_osv_GHSA_f2jm_rw3h_6phg", "grv_osv_PYSEC_2025_245",
        "grv_osv_GHSA_v3c8_3pr6_gr7p", "grv_osv_GHSA_5hq9_5r78_2gjh", "grv_osv_GHSA_pc6w_59fv_rh23",
        "grv_osv_GHSA_59p9_h35m_wg4g", "grv_osv_GHSA_7f5h_v6xp_fcq8", "grv_osv_GHSA_c67j_w6g6_q2cm",
    }
    bkp_dir = REPO_ROOT / "data" / "purge_backups"
    if bkp_dir.exists():
        for f in bkp_dir.glob("*.json"):
            try:
                bdata = json.loads(f.read_text(encoding="utf-8"))
                for r in bdata.get("rows", []):
                    if r.get("id"):
                        purged.add(r["id"])
            except Exception:
                pass
    return purged


def audit_workarounds_payload(raw_bytes: bytes) -> tuple[dict, list[str]]:
    """
    Perform Smart Monotonic Mutation & Content Gate Audit on live /workarounds.json.
    Returns (audit_info_dict, violations_list).
    """
    violations = []
    current_hash = hashlib.sha256(raw_bytes).hexdigest()
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return {"sha256": current_hash}, [f"Invalid JSON in /workarounds.json: {e}"]

    items = payload.get("workarounds", payload.get("grievances", [])) if isinstance(payload, dict) else payload
    purged_ids = load_purged_ids()

    pre2026_osv = []
    purged_present = []
    npm_corrupted = []

    for item in items:
        iid = item.get("id", "")
        if iid in purged_ids:
            purged_present.append(iid)
        if item.get("verification_tier") == "osv_verified":
            created = item.get("created_at") or ""
            if created < "2026-01-01":
                pre2026_osv.append(f"{iid} ({created})")
        combined_text = f"{item.get('symptom', '')} {item.get('workaround', '')}"
        if NPM_CORRUPTION_RE.search(combined_text):
            npm_corrupted.append(iid)

    if pre2026_osv:
        violations.append(f"Pre-2026 OSV records leaked into /workarounds.json: {pre2026_osv[:5]}")
    if purged_present:
        violations.append(f"Purged grievance IDs re-appeared in /workarounds.json: {purged_present[:5]}")
    if npm_corrupted:
        violations.append(f"Scoped npm version over-redacted as email in: {npm_corrupted[:5]}")

    prev_state = {}
    if STATE_CACHE.exists():
        try:
            prev_state = json.loads(STATE_CACHE.read_text(encoding="utf-8"))
        except Exception:
            pass

    prev_hash = prev_state.get("sha256") or (SHA256_CACHE.read_text(encoding="utf-8").strip() if SHA256_CACHE.exists() else "")
    prev_count = prev_state.get("count", len(items))
    cur_count = len(items)
    delta = cur_count - prev_count

    mutation_status = "STABLE"
    if prev_hash and prev_hash != current_hash:
        if delta >= 0 and not violations:
            mutation_status = f"HARVEST_GROWTH (+{delta} records)"
        elif delta < 0:
            # Check if a purge backup was created today
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            has_today_purge = any((REPO_ROOT / "data" / "purge_backups").glob(f"{today_str}*.json"))
            if has_today_purge and not violations:
                mutation_status = f"AUTHORIZED_PURGE ({delta} records)"
            else:
                mutation_status = f"UNEXPLAINED_DROP ({delta} records)"
                violations.append(f"Workarounds count dropped unexpectedly from {prev_count} to {cur_count}")

    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    SHA256_CACHE.write_text(current_hash, encoding="utf-8")
    STATE_CACHE.write_text(
        json.dumps({
            "sha256": current_hash,
            "count": cur_count,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2),
        encoding="utf-8",
    )

    return {
        "sha256": current_hash,
        "prev_sha256": prev_hash,
        "count": cur_count,
        "delta": delta,
        "mutation_status": mutation_status,
        "pre2026_osv_count": len(pre2026_osv),
        "purged_present_count": len(purged_present),
        "npm_corrupted_count": len(npm_corrupted),
    }, violations


def check_github_actions_health() -> tuple[dict, list[str]]:
    """Verify latest deploy.yml and harvest.yml runs on GitHub Actions did not fail or reject YAML."""
    issues = []
    summary = {}
    req = urllib.request.Request(GITHUB_RUNS_URL, headers={"User-Agent": "FMagenticL-Sentry/3.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            runs = data.get("workflow_runs", [])
            latest_by_path = {}
            for r in runs:
                path = r.get("path", "")
                if path not in latest_by_path:
                    latest_by_path[path] = r

            for wf_path in (".github/workflows/deploy.yml", ".github/workflows/harvest.yml"):
                r = latest_by_path.get(wf_path)
                if not r:
                    continue
                name = r.get("name", "")
                status = r.get("status", "")
                conclusion = r.get("conclusion")
                sha = (r.get("head_sha") or "")[:7]
                summary[wf_path] = {
                    "id": r.get("id"),
                    "name": name,
                    "status": status,
                    "conclusion": conclusion,
                    "head_sha": sha,
                    "event": r.get("event"),
                }
                if name.startswith(".github/workflows/"):
                    issues.append(f"GitHub Actions YAML parse rejection on {wf_path} (run {r.get('id')}, commit {sha}: 0 jobs run)")
                elif status == "completed" and conclusion == "failure":
                    issues.append(f"GitHub Actions workflow {name} ({wf_path}) failed on commit {sha} (run {r.get('id')})")
    except Exception as e:
        summary["error"] = str(e)
    return summary, issues


def ensure_daily_analytics_archive() -> tuple[str, bool]:
    """Ensure yesterday's UTC Cloudflare analytics archive exists in data/analytics_archive/."""
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    archive_file = REPO_ROOT / "data" / "analytics_archive" / f"analytics_{yesterday}.json"
    if archive_file.exists() and archive_file.stat().st_size > 100:
        return f"Verified ({archive_file.name}, {archive_file.stat().st_size:,} bytes)", True

    # Autonomous remediation: run archive_cf_analytics.py
    p = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "archive_cf_analytics.py"), "--date", yesterday],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=45
    )
    if archive_file.exists() and archive_file.stat().st_size > 100:
        return f"Auto-healed missing archive ({archive_file.name}, {archive_file.stat().st_size:,} bytes)", True
    return f"Archive missing for {yesterday}: {p.stderr[:120]}", False


def check_liveness_gap() -> tuple[float | None, bool]:
    if not DAILY_TELEMETRY.exists():
        return None, False
    try:
        lines = DAILY_TELEMETRY.read_text(encoding="utf-8").splitlines()
        timestamps = []
        for l in lines:
            if l.startswith("## 🕒 Sentry Diagnostic Run — "):
                raw_ts = l.replace("## 🕒 Sentry Diagnostic Run — ", "").replace(" UTC", "").strip()
                try:
                    dt = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    timestamps.append(dt)
                except Exception:
                    pass
        if timestamps:
            last_ts = timestamps[-1]
            now = datetime.now(timezone.utc)
            gap_min = (now - last_ts).total_seconds() / 60.0
            return gap_min, gap_min > 100.0
    except Exception:
        pass
    return None, False


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    now_utc = datetime.now(timezone.utc).isoformat()
    print("=" * 80)
    print(f"FMAGENTICL 90-MINUTE SENTRY v3.0 DIAGNOSTICS & ANALYTICS — {now_utc}")
    print("=" * 80)

    degraded_reasons = []
    auto_healed_actions = []

    # 0. Check Liveness Gap & Sync Upstream Bot Commits
    gap_min, gap_missed = check_liveness_gap()
    if gap_min is not None:
        gap_str = f"Last cycle was {gap_min:.1f} minutes ago."
        if gap_missed:
            gap_str += " (Note: gap > 100m; cadence resumed)"
        print(f"[0/7] Sentry Cadence Check: {gap_str}")

    sync_msg = sync_upstream_bot_commits()
    print(f"      Git Upstream Sync: {sync_msg}")
    if sync_msg.startswith("Auto-pulled"):
        auto_healed_actions.append(sync_msg)

    # 1. Probe Live Endpoints & Fast-404s
    print("\n[1/7] Probing Live Edge Endpoints, Static Shards & Fast-404 Shielding...")
    probes = probe_live_endpoints()
    for ep, p in probes.items():
        exp = p.get("expected", 200)
        if p.get("ok"):
            print(f"  {ep:<38} -> ✅ {p.get('status')} (expected {exp}, {p.get('bytes', 0):,} bytes, TTFB: {p.get('latency_ms', 0):.1f} ms)")
        else:
            print(f"  {ep:<38} -> ❌ {p.get('status')} (expected {exp}, TTFB: {p.get('latency_ms', 0):.1f} ms)")
            degraded_reasons.append(f"Live endpoint probe failed: {ep} returned {p.get('status')} (expected {exp})")

    # Verify _recent.json shard count <= 100
    recent_body = probes.get("/shards/workarounds/_recent.json", {}).get("body", b"")
    if recent_body:
        try:
            r_data = json.loads(recent_body.decode("utf-8"))
            r_cnt = len(r_data.get("workarounds", []))
            if r_cnt == 0 or r_cnt > 100:
                degraded_reasons.append(f"_recent.json shard count out of bounds: {r_cnt}")
        except Exception as e:
            degraded_reasons.append(f"_recent.json shard parse error: {e}")

    # 2. Probe MCP Protocol (including 50-item cap & <200KB check)
    print("\n[2/7] Probing MCP Protocol Endpoints (/mcp POST)...")
    mcp_probes = probe_mcp_protocol()
    for name, res in mcp_probes.items():
        if res.get("ok"):
            if "tool_count" in res:
                extra = f"tools={res['tool_count']}"
            elif "items_count" in res:
                extra = f"items={res['items_count']}/50, truncated={res['truncated']}, {res['bytes']:,}B"
            else:
                extra = f"resolved, {res.get('bytes', 0):,}B"
            print(f"  POST /mcp {name:<35} -> ✅ 200 OK ({extra}, TTFB: {res.get('latency_ms', 0):.1f} ms)")
        else:
            print(f"  POST /mcp {name:<35} -> ❌ FAILED ({res})")
            degraded_reasons.append(f"MCP protocol probe failed: {name}")

    # 3. Smart Monotonic Workarounds Mutation & Content Gate Audit
    wa_body = probes.get("/workarounds.json", {}).get("body", b"")
    if wa_body:
        audit_info, wa_violations = audit_workarounds_payload(wa_body)
        print(
            f"\n[3/7] Workarounds Content & Mutation Audit: {audit_info['mutation_status']} "
            f"(count={audit_info['count']}, delta={audit_info['delta']:+d}, "
            f"pre2026_osv={audit_info['pre2026_osv_count']}, npm_corrupt={audit_info['npm_corrupted_count']}, "
            f"SHA-256={audit_info['sha256'][:16]}...)"
        )
        for v in wa_violations:
            print(f"  ❌ {v}")
            degraded_reasons.append(v)

    # 4. Live vs Local State Reconciliation & Attribution Pin Check
    print("\n[4/7] Live vs Local State Reconciliation & 71-Truth Attribution Check...")
    live_health_body = probes.get("/v1/health", {}).get("body", b"")
    live_health = json.loads(live_health_body.decode("utf-8")) if live_health_body else {}

    local_health_path = REPO_ROOT / "dist" / "v1" / "health"
    local_health = json.loads(local_health_path.read_text(encoding="utf-8")) if local_health_path.exists() else {}

    live_wa_cnt = live_health.get("verified_workarounds", "N/A")
    local_wa_cnt = local_health.get("verified_workarounds", "N/A")
    live_grv_cnt = live_health.get("total_grievances", "N/A")
    local_grv_cnt = local_health.get("total_grievances", "N/A")
    live_bot_cnt = live_health.get("bot_harvested_grievances", "N/A")

    print(f"  Live  /v1/health: verified_workarounds={live_wa_cnt}, bot_harvested={live_bot_cnt}, total_grievances={live_grv_cnt}")
    print(f"  Local dist/health: verified_workarounds={local_wa_cnt}, total_grievances={local_grv_cnt}")

    if isinstance(live_wa_cnt, int) and live_wa_cnt < 71:
        degraded_reasons.append(f"Attribution Invariant violated: live verified_workarounds={live_wa_cnt} (< 71)")

    if live_wa_cnt != local_wa_cnt or live_grv_cnt != local_grv_cnt:
        print("  ⚠️ Live vs Local difference detected; attempting autonomous local static re-export...")
        subprocess.run([sys.executable, str(SCRIPTS_DIR / "export_db_to_static.py")], cwd=str(REPO_ROOT), capture_output=True)
        subprocess.run([sys.executable, str(SCRIPTS_DIR / "build_distribution.py")], cwd=str(REPO_ROOT), capture_output=True)
        local_health = json.loads(local_health_path.read_text(encoding="utf-8")) if local_health_path.exists() else {}
        local_wa_cnt = local_health.get("verified_workarounds", "N/A")
        local_grv_cnt = local_health.get("total_grievances", "N/A")
        if live_wa_cnt == local_wa_cnt and live_grv_cnt == local_grv_cnt:
            msg = f"Auto-synchronized local dist/ to match live D1/CDN ({live_grv_cnt} grievances / {live_wa_cnt} verified)."
            print(f"  ✅ {msg}")
            auto_healed_actions.append(msg)
        else:
            degraded_reasons.append(f"Live vs Local drift persists after re-export (Live {live_grv_cnt} != Local {local_grv_cnt})")
    else:
        print(f"  ✅ Live and local distribution in exact parity ({live_grv_cnt} grievances / {live_wa_cnt} verified / {live_bot_cnt} bot).")

    # 5. GitHub Actions CI/CD & Harvester Workflow Health
    print("\n[5/7] Checking GitHub Actions Workflow Health (deploy.yml & harvest.yml)...")
    gh_summary, gh_issues = check_github_actions_health()
    for wf, info in gh_summary.items():
        if isinstance(info, dict):
            print(f"  {wf:<35} -> status={info.get('status')}, conclusion={info.get('conclusion')}, commit={info.get('head_sha')} ({info.get('event')})")
    for iss in gh_issues:
        print(f"  ❌ {iss}")
        degraded_reasons.append(iss)

    # 6. Daily Cloudflare Analytics Archive Verification
    print("\n[6/7] Checking Daily Cloudflare Analytics Archive (30-Day Retention Guard)...")
    arch_msg, arch_ok = ensure_daily_analytics_archive()
    print(f"  Archive Status: {arch_msg}")
    if not arch_ok:
        degraded_reasons.append(arch_msg)
    elif arch_msg.startswith("Auto-healed"):
        auto_healed_actions.append(arch_msg)

    # 7. Cloudflare GraphQL Analytics, D1 State & Unique Node Audit
    print("\n[7/7] Pulling Cloudflare GraphQL Zone Traffic & D1 Attribution State...")
    cmd_cf = [sys.executable, str(SCRIPTS_DIR / "fetch_cf_analytics.py")]
    p2 = subprocess.run(cmd_cf, capture_output=True, text=True, encoding="utf-8")
    if p2.returncode == 0:
        print("  Cloudflare analytics updated in daily_telemetry.md.")
        for line in p2.stdout.splitlines():
            if line.startswith("- **") or line.startswith("### "):
                print(f"  {line}")
    else:
        print(f"  CF query warning: {p2.stderr[:200]}")
        degraded_reasons.append("Cloudflare GraphQL query failed")

    summary_path = SCRATCH_DIR / "cf_latest_summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            recent = summary.get("recent", {})
            recent_5xx = recent.get("c_5xx_total", 0)
            recent_504 = recent.get("c_504", 0)
            d1_info = summary.get("d1", {})
            if d1_info.get("error"):
                degraded_reasons.append(f"D1 Database query error: {d1_info['error']}")
            if d1_info.get("pre2026_osv_leaks", 0) > 0:
                degraded_reasons.append(f"D1 contains {d1_info['pre2026_osv_leaks']} pre-2026 OSV records!")
            if recent_5xx > 0:
                print(f"  ℹ️ Recent 4h window logged {recent_5xx} edge 5xx responses ({recent_504} 504s; tracked honestly).")
        except Exception:
            pass

    cmd_ips = [sys.executable, str(SCRATCH_DIR / "audit_unique_mcp_ips.py")]
    p3 = subprocess.run(cmd_ips, capture_output=True, text=True, encoding="utf-8")
    if p3.returncode == 0:
        print("\n  Distinct Nodes Audit:")
        for line in p3.stdout.splitlines():
            if "Total Distinct" in line or "/mcp Methods Breakdown" in line:
                print(f"  {line.strip()}")

    if auto_healed_actions:
        print("\n🔧 AUTONOMOUS SELF-HEALING ACTIONS EXECUTED:")
        for act in auto_healed_actions:
            print(f"  - 🛠️ {act}")

    print("\n" + "=" * 80)
    if not degraded_reasons:
        print("DIAGNOSTICS & TELEMETRY CYCLE COMPLETE — ALL ENDPOINTS & INVARIANTS GREEN")
        print("=" * 80)
        sys.exit(0)
    else:
        print("DIAGNOSTICS & TELEMETRY CYCLE: DEGRADED STATUS REPORTED")
        print("DEGRADED REASONS:")
        for r in degraded_reasons:
            print(f"  - ❌ {r}")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
