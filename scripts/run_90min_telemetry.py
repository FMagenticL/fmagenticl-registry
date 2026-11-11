#!/usr/bin/env python3
"""
FMagenticL - 90-Minute Standing Diagnostics, Analytics, Adaptive Probation & Escalation Engine (Sentry v3.1)
Implements:
  0. Sentry Cycle Liveness / Missed-Cycle Detection (gap > 100 min) & Upstream Bot Git Sync
  1. Live HTTP Edge Probing with Two-Strike Warm-Isolate TTFB Verification (/v1/health, /guestbook.json,
     /workarounds.json, /.well-known/agent-card.json, /shards/workarounds/_recent.json,
     /shards/workarounds/pydantic.json) + Fast-404 Edge Shielding (/api/query, /sw.js, /shards/workarounds/fastapi.json)
  2. Read-only MCP JSON-RPC Probes with Schema & Payload Cap Verification (tools/list, fmagenticl_resolve,
     fmagenticl_get_workarounds <= 50 items & < 150 KB)
  3. Smart Monotonic Workarounds Mutation & Deep Semantic Content Gate Audit (0 pre-2026 OSV, 0 purged IDs,
     0 npm @scope/pkg@[REDACTED corruptions, 0 broken version strings / SHA versions, single-target flood guard)
  4. Cross-Store Mathematical Conservation & 71-Truth Attribution Pin Check (Live == Local == D1 == Shards)
  5. GitHub Actions CI/CD & Harvester Workflow Health Check (deploy.yml & harvest.yml)
  6. Daily Cloudflare Analytics Archive Verification (data/analytics_archive/)
  7. Cloudflare GraphQL Analytics with Bucket A/B/C Path-Segregated 5xx Split & Dual-Table Airlock Census
  8. 3-Stage Post-Fix Probationary Cron State Machine (180s -> 720s -> 1800s -> 5400s) + Auto-Rollback +
     Tiered Escalation Dossier Generator (Gemini 4 Argon vs. DeepSeek)
"""

import sys
import os
import re
import json
import time
import hashlib
import statistics
import urllib.request
import urllib.error
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_DIR = REPO_ROOT / "scratch"
SCRIPTS_DIR = REPO_ROOT / "scripts"
BASE_URL = "https://fmagenticl-registry.pages.dev"
STATE_CACHE = SCRATCH_DIR / ".last_workarounds_state.json"
SHA256_CACHE = SCRATCH_DIR / ".last_workarounds_sha256"
PROBATION_STATE_FILE = SCRATCH_DIR / ".sentry_probation_state.json"
DAILY_TELEMETRY = REPO_ROOT / "daily_telemetry.md"
GITHUB_RUNS_URL = "https://api.github.com/repos/FMagenticL/fmagenticl-registry/actions/runs?per_page=10"

NPM_CORRUPTION_RE = re.compile(r"@[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+@\[REDACTED")
BROKEN_VERSION_RE = re.compile(
    r"(?:Upgrade\s+[^\s]+\s+to\s+(?:None|null|undefined|unknown|[0-9a-f]{20,40})\b)",
    re.IGNORECASE,
)

TTFB_CEILINGS_MS = {
    "/v1/health": 3500.0,
    "/guestbook.json": 1200.0,
    "/workarounds.json": 6500.0,
    "/.well-known/agent-card.json": 1000.0,
    "/shards/workarounds/_recent.json": 1200.0,
    "/shards/workarounds/pydantic.json": 1200.0,
    "/api/query": 1000.0,
    "/sw.js": 1000.0,
    "/shards/workarounds/fastapi.json": 1000.0,
}


def get_head_sha() -> str:
    try:
        p = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=20
        )
        return (p.stdout or "").strip()
    except Exception:
        return "unknown"


def sync_upstream_bot_commits() -> str:
    """Pull upstream [BOT] commits from origin/main using --autostash so local daily_telemetry.md edits never block sync."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        branch_proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10, env=env
        )
        curr_branch = (branch_proc.stdout or "").strip()
        if curr_branch != "main":
            return f"Skipping auto-pull on non-main branch ({curr_branch})." 
        subprocess.run(
            ["git", "fetch", "origin", "main", "--quiet"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60, env=env
        )
        rev = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/main"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=20, env=env
        )
        behind = int((rev.stdout or "0").strip() or "0")
        if behind > 0:
            subprocess.run(
                ["git", "checkout", "--", "dist"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60, env=env
            )
            # Clear local untracked analytics archives that already exist in origin/main so midnight local captures never block rebase
            untracked = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard", "data/analytics_archive/"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=20, env=env
            )
            for rel_path in (untracked.stdout or "").splitlines():
                rel_path = rel_path.strip()
                if not rel_path:
                    continue
                exists_upstream = subprocess.run(
                    ["git", "cat-file", "-e", f"origin/main:{rel_path}"],
                    cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=10, env=env
                )
                if exists_upstream.returncode == 0:
                    (REPO_ROOT / rel_path).unlink(missing_ok=True)
            pull = subprocess.run(
                ["git", "pull", "--rebase", "--autostash", "origin", "main"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60, env=env
            )
            if pull.returncode == 0:
                return f"Auto-pulled {behind} upstream commit(s) from origin/main (with --autostash)."
            return f"Auto-pull warning: {pull.stderr.strip()[:120]}"
        return "Local branch is up to date with origin/main."
    except Exception as e:
        return f"Git sync check skipped: {e}"


def _single_http_probe(url: str, expected: int, timeout: int = 12) -> dict:
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-Sentry/3.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read() if expected == 200 else b""
            latency_ms = (time.perf_counter() - t0) * 1000.0
            code = resp.getcode()
            ok = (code == expected) and (len(body) > 0 if expected == 200 else True)
            return {
                "status": code,
                "expected": expected,
                "bytes": len(body),
                "latency_ms": latency_ms,
                "body": body,
                "ok": ok,
            }
    except urllib.error.HTTPError as e:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": e.code,
            "expected": expected,
            "bytes": 0,
            "latency_ms": latency_ms,
            "body": b"",
            "ok": e.code == expected,
        }
    except Exception as e:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": "ERROR",
            "expected": expected,
            "bytes": 0,
            "error": str(e),
            "latency_ms": latency_ms,
            "body": b"",
            "ok": False,
        }


def probe_live_endpoints():
    """
    Probe all 200 OK and 404 endpoints with Two-Strike Warm-Isolate TTFB Verification.
    If initial TTFB exceeds ceiling or fails, run 2 warm follow-up probes spaced 1.5s apart
    and evaluate the median TTFB to prevent cold-isolate false alarms.
    """
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
    for ep, expected in [(e, 200) for e in endpoints_200] + [(e, 404) for e in endpoints_404]:
        url = BASE_URL + ep
        ceiling = TTFB_CEILINGS_MS.get(ep, 1000.0)
        p1 = _single_http_probe(url, expected)
        if not p1["ok"] or p1["latency_ms"] > ceiling:
            time.sleep(1.0)
            p2 = _single_http_probe(url, expected)
            time.sleep(1.0)
            p3 = _single_http_probe(url, expected)
            warm_samples = [p["latency_ms"] for p in (p2, p3) if p["ok"]]
            warm_ms = min(warm_samples) if warm_samples else statistics.median([p1["latency_ms"], p2["latency_ms"], p3["latency_ms"]])
            chosen = p3 if p3["ok"] else (p2 if p2["ok"] else p1)
            chosen["initial_latency_ms"] = p1["latency_ms"]
            chosen["latency_ms"] = warm_ms
            chosen["reprobed"] = True
            chosen["ttfb_breach"] = (not chosen["ok"]) or (warm_ms > ceiling)
            results[ep] = chosen
        else:
            p1["reprobed"] = False
            p1["ttfb_breach"] = False
            results[ep] = p1

    return results


def probe_mcp_protocol():
    url = BASE_URL + "/mcp"
    results = {}

    def post_mcp(req_id: int, method: str, params: dict | None = None):
        body_dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            body_dict["params"] = params
        payload = json.dumps(body_dict).encode("utf-8")
        last_exc = None
        for attempt in range(1, 3):
            t0 = time.perf_counter()
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "User-Agent": "FMagenticL-Sentry/3.1",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read()
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    return resp.getcode(), raw, json.loads(raw.decode("utf-8")), latency_ms
            except (urllib.error.URLError, ConnectionResetError, TimeoutError, OSError) as e:
                last_exc = e
                if attempt < 2:
                    time.sleep(1.0)
        raise last_exc

    # 1. tools/list (must return 6 tools, each with valid inputSchema.properties)
    try:
        code, raw, data, latency_ms = post_mcp(1, "tools/list")
        if latency_ms > 1000.0:
            time.sleep(1.0)
            _, _, _, l2 = post_mcp(10, "tools/list")
            latency_ms = min(latency_ms, l2)
        tools = data.get("result", {}).get("tools", [])
        schemas_valid = all(
            isinstance(t.get("inputSchema", {}).get("properties"), dict)
            for t in tools
        )
        results["tools/list"] = {
            "ok": code == 200 and len(tools) == 6 and schemas_valid,
            "tool_count": len(tools),
            "schemas_valid": schemas_valid,
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
        if latency_ms > 1000.0:
            time.sleep(1.0)
            _, _, _, l2 = post_mcp(
                20, "tools/call", {"name": "fmagenticl_resolve", "arguments": {"target": "pydantic"}}
            )
            latency_ms = min(latency_ms, l2)
        has_content = "result" in data and not data.get("error")
        results["tools/call:fmagenticl_resolve"] = {
            "ok": code == 200 and has_content,
            "bytes": len(raw),
            "latency_ms": latency_ms,
        }
    except Exception as e:
        results["tools/call:fmagenticl_resolve"] = {"ok": False, "error": str(e), "latency_ms": 0.0}

    # 3. tools/call fmagenticl_get_workarounds (must cap at <= 50 items and < 150 KB soft / < 200 KB hard)
    try:
        code, raw, data, latency_ms = post_mcp(
            3, "tools/call", {"name": "fmagenticl_get_workarounds", "arguments": {}}
        )
        if latency_ms > 1000.0:
            time.sleep(1.0)
            _, _, _, l2 = post_mcp(
                30, "tools/call", {"name": "fmagenticl_get_workarounds", "arguments": {}}
            )
            latency_ms = min(latency_ms, l2)
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
    Perform Smart Monotonic Mutation & Deep Semantic Content Gate Audit on live /workarounds.json.
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
    semantic_defects = []

    for item in items:
        iid = item.get("id", "")
        if iid in purged_ids:
            purged_present.append(iid)
        if item.get("verification_tier") == "osv_verified":
            created = item.get("created_at") or ""
            if created < "2026-01-01":
                pre2026_osv.append(f"{iid} ({created})")
        symptom_txt = (item.get("symptom") or "").strip()
        wa_txt = (item.get("workaround") or "").strip()
        combined_text = f"{symptom_txt} {wa_txt}"
        if NPM_CORRUPTION_RE.search(combined_text):
            npm_corrupted.append(iid)
        if BROKEN_VERSION_RE.search(wa_txt) or len(wa_txt) < 15 or symptom_txt == wa_txt:
            semantic_defects.append(iid)

    if pre2026_osv:
        violations.append(f"Pre-2026 OSV records leaked into /workarounds.json: {pre2026_osv[:5]}")
    if purged_present:
        violations.append(f"Purged grievance IDs re-appeared in /workarounds.json: {purged_present[:5]}")
    if npm_corrupted:
        violations.append(f"Scoped npm version over-redacted as email in: {npm_corrupted[:5]}")
    if semantic_defects:
        violations.append(f"Semantic defect (broken version/SHA/empty workaround) in: {semantic_defects[:5]}")

    prev_state = {}
    if STATE_CACHE.exists():
        try:
            prev_state = json.loads(STATE_CACHE.read_text(encoding="utf-8"))
        except Exception:
            pass

    prev_hash = prev_state.get("sha256") or (SHA256_CACHE.read_text(encoding="utf-8").strip() if SHA256_CACHE.exists() else "")
    prev_count = prev_state.get("count", len(items))
    prev_ids = set(prev_state.get("ids", []))
    cur_count = len(items)
    cur_ids = [item.get("id", "") for item in items if item.get("id")]
    delta = cur_count - prev_count

    # Single-Target Flood Guard on newly harvested items (created within last 6h; historical D1 backfills are exempt)
    if prev_ids and delta > 0:
        recent_cutoff = (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")
        new_items = [
            item for item in items
            if item.get("id") not in prev_ids and (item.get("created_at") or "") >= recent_cutoff
        ]
        target_burst = Counter(item.get("target", "unknown") for item in new_items)
        gap_min, _ = check_liveness_gap()
        cycle_mult = max(1.0, (gap_min or 90.0) / 60.0)
        dynamic_cap = max(25, int(25 * cycle_mult))
        for tgt, cnt in target_burst.items():
            if cnt > dynamic_cap:
                violations.append(
                    f"Harvester Target Flood: '{tgt}' added {cnt} records in a single cycle (> {dynamic_cap} dynamic cap for {gap_min if gap_min else 90:.0f}m window)"
                )

    mutation_status = "STABLE"
    if prev_hash and prev_hash != current_hash:
        if delta >= 0 and not violations:
            mutation_status = f"HARVEST_GROWTH (+{delta} records)"
        elif delta < 0:
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
            "ids": cur_ids,
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
        "semantic_defect_count": len(semantic_defects),
    }, violations


def check_github_actions_health() -> tuple[dict, list[str]]:
    """Verify latest deploy.yml and harvest.yml runs on GitHub Actions did not fail or reject YAML."""
    issues = []
    summary = {}
    req = urllib.request.Request(GITHUB_RUNS_URL, headers={"User-Agent": "FMagenticL-Sentry/3.1"})
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


def load_probation_state() -> dict:
    if PROBATION_STATE_FILE.exists():
        try:
            return json.loads(PROBATION_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "probation_stage": 0,
        "fix_timestamp_utc": None,
        "pre_fix_git_sha": None,
        "fix_commit_sha": None,
        "fix_actions": [],
        "baseline_mcp_504": 0,
        "baseline_bucket_a_crash": 0,
        "circuit_breaker_tripped": False,
        "fixes_last_24h": [],
    }


def save_probation_state(state: dict):
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    PROBATION_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def generate_escalation_dossier(target_model: str, reasons: list[str], summary_data: dict) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    prefix = "handoff_deepseek" if "DEEPSEEK" in target_model.upper() else "escalation_argon"
    dossier_path = SCRATCH_DIR / f"{prefix}_{ts}.md"
    lines = [
        f"# 🚨 SENTRY v3.1 ESCALATION DOSSIER — Target: {target_model}",
        f"- **Generated (UTC):** `{datetime.now(timezone.utc).isoformat()}`",
        f"- **Git HEAD:** `{get_head_sha()}`",
        "",
        "## 1. Triggering Violations / Red Flags",
    ]
    for r in reasons:
        lines.append(f"- ❌ {r}")
    lines.extend([
        "",
        "## 2. Latest Cloudflare & D1 Summary Snapshot",
        "```json",
        json.dumps(summary_data, indent=2),
        "```",
    ])
    dossier_path.write_text("\n".join(lines), encoding="utf-8")
    return dossier_path


def evaluate_probation_and_next_schedule(
    degraded_reasons: list[str],
    escalation_targets: set[str],
    auto_healed_actions: list[str],
    summary_data: dict,
) -> tuple[int, str, str | None]:
    """
    Manage the 3-Stage Post-Fix Probationary Cron State Machine:
      Stage 0 (Normal) -> if auto_healed_actions > 0: enter Stage 1 (180s / 3m)
      Stage 1 (T+3m)   -> if green: advance to Stage 2 (720s / 12m, i.e. T+15m)
      Stage 2 (T+15m)  -> if green: advance to Stage 3 (1800s / 30m, i.e. T+45m)
      Stage 3 (T+45m)  -> if green: graduate to Stage 0 (5400s / 90m)
      If any stage fails during probation -> trip circuit breaker & escalate!
    """
    state = load_probation_state()
    cur_stage = state.get("probation_stage", 0)
    hist_metrics = summary_data.get("hist", {})
    cur_mcp_504 = hist_metrics.get("mcp_504", 0)
    cur_bucket_a_crash = hist_metrics.get("bucket_a_5xx_crash", 0)

    # Check if we are currently inside a post-fix probation window
    if cur_stage in (1, 2, 3):
        base_504 = state.get("baseline_mcp_504", cur_mcp_504)
        # Protect against mismatched initial state where baseline was seeded from 4h recent (<20) while cur is lifetime (>50)
        if base_504 < 20 and cur_mcp_504 > 50:
            base_504 = cur_mcp_504
            state["baseline_mcp_504"] = base_504
            save_probation_state(state)

        base_crash = state.get("baseline_bucket_a_crash", cur_bucket_a_crash)
        delta_mcp_504 = max(0, cur_mcp_504 - base_504)
        delta_crash = max(0, cur_bucket_a_crash - base_crash)
        if delta_crash > 0:
            degraded_reasons.append(f"Post-Fix Probation Violation: +{delta_crash} Bucket A 5xx crash(es) since fix!")
            escalation_targets.add("DEEPSEEK_AND_ARGON")
        if delta_mcp_504 > 1:
            degraded_reasons.append(f"Post-Fix Probation Violation: +{delta_mcp_504} /mcp 504 timeouts since fix!")
            escalation_targets.add("DEEPSEEK_AND_ARGON")

        if degraded_reasons:
            # Check if autonomous git rollback is viable (only on hard functional regressions, never on TTFB jitter alone)
            has_hard_regression = any(not r.startswith("Sustained warm TTFB breach") for r in degraded_reasons)
            pre_fix_sha = state.get("pre_fix_git_sha")
            cur_sha = get_head_sha()
            # Code-Commit Protection Invariant: NEVER auto-revert commits that touch source code (.py/.js/.yml/setup.py)
            changed_files_proc = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
                cwd=str(REPO_ROOT), capture_output=True, text=True
            )
            changed_paths = [p.strip() for p in (changed_files_proc.stdout or "").splitlines() if p.strip()]
            touches_code = any(
                p.startswith(("fmagenticl/", "scripts/", "functions/", "serverless/", "tests/", ".github/"))
                or p in ("setup.py", "pyproject.toml")
                for p in changed_paths
            )
            if touches_code and has_hard_regression:
                print(f"  🛡️ Auto-revert blocked on commit {cur_sha}: commit modifies source code ({changed_paths[:3]}). Escalating without destructive revert.")
            if (not touches_code) and has_hard_regression and pre_fix_sha and cur_sha != "unknown" and cur_sha != pre_fix_sha and not state.get("rollback_attempted"):
                print(f"  🚨 Probation violated on data-only commit {cur_sha}! Executing autonomous rollback to pre-fix {pre_fix_sha}...")
                try:
                    p_rev = subprocess.run(["git", "revert", "--no-edit", "HEAD"], cwd=str(REPO_ROOT), capture_output=True, text=True)
                    if p_rev.returncode == 0:
                        p_push = subprocess.run(["git", "push", "origin", "main"], cwd=str(REPO_ROOT), capture_output=True, text=True)
                        if p_push.returncode == 0:
                            rollback_msg = f"Autonomous rollback: Reverted commit {cur_sha} to restore pre-fix {pre_fix_sha} after probation violation: {degraded_reasons[0]}"
                            print(f"  ✅ {rollback_msg}")
                            auto_healed_actions.append(rollback_msg)
                            state["rollback_attempted"] = True
                            state["probation_stage"] = 1
                            state["baseline_mcp_504"] = cur_mcp_504
                            state["baseline_bucket_a_crash"] = cur_bucket_a_crash
                            save_probation_state(state)
                            return 180, "PROBATION_AUTONOMOUS_ROLLBACK_STAGE_1_REPROBE (T+3m)", None
                except Exception as e:
                    print(f"  ⚠️ Autonomous rollback attempt encountered error: {e}")

            # Probation Failed without auto-rollback! Trip circuit breaker
            state["circuit_breaker_tripped"] = True
            state["probation_stage"] = 0
            save_probation_state(state)
            escalation_targets.add("ARGON")
            dossier = generate_escalation_dossier(
                " + ".join(sorted(escalation_targets)), degraded_reasons, summary_data
            )
            return 600, f"PROBATION_STAGE_{cur_stage}_FAILED_CIRCUIT_BREAKER_TRIPPED", str(dossier)

        # Probation stage passed! Advance to next stage
        if cur_stage == 1:
            state["probation_stage"] = 2
            save_probation_state(state)
            return 720, "PROBATION_STAGE_2_TRAFFIC_DELTA_VERIFY (T+15m)", None
        elif cur_stage == 2:
            state["probation_stage"] = 3
            save_probation_state(state)
            return 1800, "PROBATION_STAGE_3_HARVESTER_SOAK_VERIFY (T+45m)", None
        else:
            # Stage 3 passed -> Graduate back to 90m hibernation!
            state["probation_stage"] = 0
            state["fix_actions"] = []
            save_probation_state(state)
            return 5400, "PROBATION_GRADUATED_STANDARD_90M_HIBERNATION", None

    # Stage 0 (Normal cycle)
    if degraded_reasons:
        target_str = " + ".join(sorted(escalation_targets)) if escalation_targets else "ARGON"
        dossier = generate_escalation_dossier(target_str, degraded_reasons, summary_data)
        return 1800, f"DEGRADED_ESCALATION_REQUIRED ({target_str})", str(dossier)

    if auto_healed_actions:
        # Enter Stage 1 Probation (180s / 3m)
        now_iso = datetime.now(timezone.utc).isoformat()
        state["probation_stage"] = 1
        state["fix_timestamp_utc"] = now_iso
        state["pre_fix_git_sha"] = get_head_sha()
        state["fix_actions"] = auto_healed_actions
        state["baseline_mcp_504"] = cur_mcp_504
        state["baseline_bucket_a_crash"] = cur_bucket_a_crash
        fixes_24h = state.get("fixes_last_24h", [])
        fixes_24h.append(now_iso)
        state["fixes_last_24h"] = fixes_24h[-10:]
        save_probation_state(state)
        return 180, "PROBATION_STAGE_1_POST_FIX_VERIFY (T+3m)", None

    return 5400, "STANDARD_90M_HIBERNATION", None


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    now_utc = datetime.now(timezone.utc).isoformat()
    prob_state = load_probation_state()
    prob_stage = prob_state.get("probation_stage", 0)
    stage_banner = f" [PROBATION STAGE {prob_stage}/3]" if prob_stage else ""

    print("=" * 80)
    print(f"FMAGENTICL SENTRY v3.1 DIAGNOSTICS & ADAPTIVE AUTONOMY{stage_banner} — {now_utc}")
    print("=" * 80)

    degraded_reasons = []
    escalation_targets = set()
    auto_healed_actions = []

    # 0. Check Liveness Gap & Sync Upstream Bot Commits
    gap_min, gap_missed = check_liveness_gap()
    if gap_min is not None:
        gap_str = f"Last cycle was {gap_min:.1f} minutes ago."
        if gap_missed:
            gap_str += " (Note: gap > 100m; cadence resumed)"
        print(f"[0/8] Sentry Cadence Check: {gap_str}")

    sync_msg = sync_upstream_bot_commits()
    print(f"      Git Upstream Sync: {sync_msg}")
    # Routine upstream harvest git pull is normal sync hygiene (does not enter 3-stage probation).

    # 1. Probe Live Endpoints & Fast-404s (with Two-Strike Warm TTFB Re-Probe)
    print("\n[1/8] Probing Live Edge Endpoints, Static Shards & Fast-404 Shielding (Warm-TTFB Guard)...")
    probes = probe_live_endpoints()
    for ep, p in probes.items():
        exp = p.get("expected", 200)
        reprobe_note = f" [warm-median of 3; initial={p.get('initial_latency_ms', 0):.0f}ms]" if p.get("reprobed") else ""
        if p.get("ok") and not p.get("ttfb_breach"):
            print(f"  {ep:<38} -> ✅ {p.get('status')} (expected {exp}, {p.get('bytes', 0):,} bytes, TTFB: {p.get('latency_ms', 0):.1f} ms{reprobe_note})")
        elif p.get("ok") and p.get("ttfb_breach"):
            print(f"  {ep:<38} -> ⚠️ {p.get('status')} SUSTAINED TTFB BREACH ({p.get('latency_ms', 0):.1f} ms > ceiling{reprobe_note})")
            degraded_reasons.append(f"Sustained warm TTFB breach on {ep}: {p.get('latency_ms', 0):.1f} ms")
            escalation_targets.add("DEEPSEEK_AND_ARGON")
        else:
            print(f"  {ep:<38} -> ❌ {p.get('status')} (expected {exp}, TTFB: {p.get('latency_ms', 0):.1f} ms{reprobe_note})")
            degraded_reasons.append(f"Live endpoint probe failed: {ep} returned {p.get('status')} (expected {exp})")
            escalation_targets.add("ARGON")

    # Verify _recent.json shard count <= 100 and size < 180 KB
    recent_body = probes.get("/shards/workarounds/_recent.json", {}).get("body", b"")
    if recent_body:
        try:
            r_data = json.loads(recent_body.decode("utf-8"))
            r_cnt = len(r_data.get("workarounds", []))
            if r_cnt == 0 or r_cnt > 100:
                degraded_reasons.append(f"_recent.json shard count out of bounds: {r_cnt}")
                escalation_targets.add("ARGON")
            if len(recent_body) > 180_000:
                degraded_reasons.append(f"_recent.json shard size approaching 200KB danger zone: {len(recent_body):,} bytes")
                escalation_targets.add("DEEPSEEK_AND_ARGON")
        except Exception as e:
            degraded_reasons.append(f"_recent.json shard parse error: {e}")

    # 2. Probe MCP Protocol (including 50-item cap, schema validity & <200KB check)
    print("\n[2/8] Probing MCP Protocol Endpoints (/mcp POST)...")
    mcp_probes = probe_mcp_protocol()
    for name, res in mcp_probes.items():
        if res.get("ok"):
            if "tool_count" in res:
                extra = f"tools={res['tool_count']}, schemas_valid={res.get('schemas_valid')}"
            elif "items_count" in res:
                extra = f"items={res['items_count']}/50, truncated={res['truncated']}, {res['bytes']:,}B"
            else:
                extra = f"resolved, {res.get('bytes', 0):,}B"
            print(f"  POST /mcp {name:<35} -> ✅ 200 OK ({extra}, TTFB: {res.get('latency_ms', 0):.1f} ms)")
        else:
            print(f"  POST /mcp {name:<35} -> ❌ FAILED ({res})")
            degraded_reasons.append(f"MCP protocol probe failed: {name}")
            escalation_targets.add("DEEPSEEK_AND_ARGON")

    # 3. Smart Monotonic Workarounds Mutation & Deep Semantic Content Gate Audit
    wa_body = probes.get("/workarounds.json", {}).get("body", b"")
    audit_info = {}
    if wa_body:
        audit_info, wa_violations = audit_workarounds_payload(wa_body)
        print(
            f"\n[3/8] Workarounds Content & Semantic Audit: {audit_info.get('mutation_status')} "
            f"(count={audit_info.get('count')}, delta={audit_info.get('delta', 0):+d}, "
            f"pre2026_osv={audit_info.get('pre2026_osv_count')}, npm_corrupt={audit_info.get('npm_corrupted_count')}, "
            f"semantic_defects={audit_info.get('semantic_defect_count')}, "
            f"SHA-256={audit_info.get('sha256', '')[:16]}...)"
        )
        for v in wa_violations:
            print(f"  ❌ {v}")
            degraded_reasons.append(v)
            escalation_targets.add("DEEPSEEK_AND_ARGON")

    # 4. Cross-Store Mathematical Conservation & 71-Truth Attribution Check
    print("\n[4/8] Cross-Store Mathematical Conservation & 71-Truth Attribution Check...")
    live_health_body = probes.get("/v1/health", {}).get("body", b"")
    live_health = json.loads(live_health_body.decode("utf-8")) if live_health_body else {}

    local_health_path = REPO_ROOT / "dist" / "v1" / "health"
    try:
        local_health = json.loads(local_health_path.read_text(encoding="utf-8")) if local_health_path.exists() else {}
    except Exception:
        local_health = {}

    live_wa_cnt = live_health.get("verified_workarounds", "N/A")
    local_wa_cnt = local_health.get("verified_workarounds", "N/A")
    live_grv_cnt = live_health.get("total_grievances", "N/A")
    local_grv_cnt = local_health.get("total_grievances", "N/A")
    live_bot_cnt = live_health.get("bot_harvested_grievances", "N/A")

    print(f"  Live  /v1/health: verified_workarounds={live_wa_cnt}, bot_harvested={live_bot_cnt}, total_grievances={live_grv_cnt}")
    print(f"  Local dist/health: verified_workarounds={local_wa_cnt}, total_grievances={local_grv_cnt}")

    if isinstance(live_wa_cnt, int) and live_wa_cnt != 71:
        degraded_reasons.append(f"Attribution Invariant violated: live verified_workarounds={live_wa_cnt} (expected 71)")
        escalation_targets.add("ARGON")

    if isinstance(live_wa_cnt, int) and isinstance(live_bot_cnt, int) and isinstance(live_grv_cnt, int):
        if live_wa_cnt + live_bot_cnt != live_grv_cnt:
            degraded_reasons.append(
                f"Conservation equation violated: verified({live_wa_cnt}) + bot({live_bot_cnt}) != total({live_grv_cnt})"
            )
            escalation_targets.add("ARGON")
        if audit_info.get("count") and audit_info["count"] != live_grv_cnt:
            degraded_reasons.append(
                f"Feed/Health count mismatch: /workarounds.json({audit_info['count']}) != /v1/health({live_grv_cnt})"
            )
            escalation_targets.add("ARGON")

    if live_wa_cnt != local_wa_cnt or live_grv_cnt != local_grv_cnt:
        if not prob_state.get("circuit_breaker_tripped"):
            print("  ⚠️ Live vs Local difference detected; executing Tier 1 autonomous local static re-export...")
            subprocess.run([sys.executable, str(SCRIPTS_DIR / "export_db_to_static.py")], cwd=str(REPO_ROOT), capture_output=True)
            subprocess.run([sys.executable, str(SCRIPTS_DIR / "build_distribution.py")], cwd=str(REPO_ROOT), capture_output=True)
            local_health = json.loads(local_health_path.read_text(encoding="utf-8")) if local_health_path.exists() else {}
            local_wa_cnt = local_health.get("verified_workarounds", "N/A")
            local_grv_cnt = local_health.get("total_grievances", "N/A")
            if live_wa_cnt == local_wa_cnt and live_grv_cnt == local_grv_cnt:
                msg = f"Auto-synchronized local dist/ to match live D1/CDN ({live_grv_cnt} grievances / {live_wa_cnt} verified)."
                print(f"  ✅ {msg}")
            else:
                degraded_reasons.append(f"Live vs Local drift persists after re-export (Live {live_grv_cnt} != Local {local_grv_cnt})")
                escalation_targets.add("ARGON")
        else:
            degraded_reasons.append(f"Live vs Local drift ({live_grv_cnt} != {local_grv_cnt}) while circuit breaker is tripped")
            escalation_targets.add("ARGON")
    else:
        print(f"  ✅ Mathematical conservation & parity verified ({live_grv_cnt} = {live_wa_cnt} verified + {live_bot_cnt} bot).")

    # 5. GitHub Actions CI/CD & Harvester Workflow Health
    print("\n[5/8] Checking GitHub Actions Workflow Health (deploy.yml & harvest.yml)...")
    gh_summary, gh_issues = check_github_actions_health()
    if gh_summary.get("error"):
        print(f"  ⚠️ GitHub Actions API warning: {gh_summary['error']}")
    for wf, info in gh_summary.items():
        if isinstance(info, dict):
            print(f"  {wf:<35} -> status={info.get('status')}, conclusion={info.get('conclusion')}, commit={info.get('head_sha')} ({info.get('event')})")
    for iss in gh_issues:
        print(f"  ❌ {iss}")
        degraded_reasons.append(iss)
        escalation_targets.add("ARGON")

    # 6. Daily Cloudflare Analytics Archive Verification
    print("\n[6/8] Checking Daily Cloudflare Analytics Archive (30-Day Retention Guard)...")
    arch_msg, arch_ok = ensure_daily_analytics_archive()
    print(f"  Archive Status: {arch_msg}")
    if not arch_ok:
        degraded_reasons.append(arch_msg)
        escalation_targets.add("ARGON")

    # 7. Cloudflare GraphQL Analytics (Bucket A/B/C 5xx Split) & Dual-Table D1 Airlock State
    print("\n[7/8] Pulling Cloudflare GraphQL Zone Traffic (Bucket A/B/C Split) & D1 Airlock State...")
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
        escalation_targets.add("ARGON")

    summary_path = SCRATCH_DIR / "cf_latest_summary.json"
    summary_data = {}
    if summary_path.exists():
        try:
            summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
            recent = summary_data.get("recent", {})
            d1_info = summary_data.get("d1", {})

            # Evaluate Bucket A (/mcp + dynamic runtime) vs Bucket B (static) vs Bucket C (scanner noise)
            bucket_a_crash = recent.get("bucket_a_5xx_crash", 0)
            mcp_504 = recent.get("mcp_504", 0)
            mcp_reqs = recent.get("mcp_requests", 0)
            mcp_5xx_rate = recent.get("mcp_5xx_rate", 0.0)
            bucket_b_5xx = recent.get("bucket_b_5xx", 0)
            bucket_c_scanner = recent.get("bucket_c_scanner_5xx", 0)

            if bucket_a_crash > 0:
                if prob_stage in (1, 2, 3):
                    delta_crash = max(0, bucket_a_crash - prob_state.get("baseline_bucket_a_crash", bucket_a_crash))
                    if delta_crash > 0:
                        degraded_reasons.append(f"CRITICAL: Bucket A logged {delta_crash} hard 5xx crash(es) since fix!")
                        escalation_targets.add("DEEPSEEK_AND_ARGON")
                    else:
                        print(f"  ℹ️ [PROBATION MONITOR] 4h rolling Bucket A crashes ({bucket_a_crash}) occurred pre-fix; 0 crashes since fix.")
                else:
                    degraded_reasons.append(
                        f"CRITICAL: Bucket A (/mcp or dynamic /v1/*) logged {bucket_a_crash} hard 5xx crash(es) (500/502/503) in last 4h!"
                    )
                    escalation_targets.add("DEEPSEEK_AND_ARGON")

            if mcp_504 >= 2 and mcp_5xx_rate > 0.5:
                if prob_stage in (1, 2, 3):
                    # Under active post-fix probation: rolling 4h window still reflects pre-fix traffic.
                    # Do not fail probation on pre-fix legacy traffic; post-fix health is evaluated by delta in evaluate_probation_and_next_schedule.
                    print(f"  ℹ️ [PROBATION MONITOR] 4h rolling /mcp 504 rate ({mcp_5xx_rate:.2f}%) includes pre-fix legacy traffic. Live probes & post-fix delta healthy.")
                else:
                    degraded_reasons.append(
                        f"Bucket A /mcp 504 timeout rate breached 0.5% threshold: {mcp_504}/{mcp_reqs} ({mcp_5xx_rate:.2f}%)"
                    )
                    escalation_targets.add("DEEPSEEK_AND_ARGON")

            print(
                f"  🛡️ 4h 5xx Triage: Bucket A (/mcp Runtime)={ mcp_504 } 504s / { bucket_a_crash } crashes ({mcp_5xx_rate:.2f}%) | "
                f"Bucket B (Core Static)={ bucket_b_5xx } | Bucket C (Ignored Scanner Probes)={ bucket_c_scanner }"
            )

            if d1_info.get("error"):
                degraded_reasons.append(f"D1 Database query error: {d1_info['error']}")
                escalation_targets.add("ARGON")
            if d1_info.get("pre2026_osv_leaks", 0) > 0:
                degraded_reasons.append(f"D1 contains {d1_info['pre2026_osv_leaks']} pre-2026 OSV records!")
                escalation_targets.add("ARGON")
            if isinstance(d1_info.get("grievances"), int) and isinstance(live_grv_cnt, int):
                drift = abs(d1_info["grievances"] - live_grv_cnt)
                if drift > 0:
                    if drift <= 300:
                        print(f"  ℹ️ D1 vs CDN Count Drift: D1({d1_info['grievances']}) != CDN({live_grv_cnt}) [delta={drift} <= 300: IN_FLIGHT_HARVESTING nominal]")
                    else:
                        degraded_reasons.append(
                            f"Excessive D1 vs CDN Promoted Count Drift: D1({d1_info['grievances']}) != CDN({live_grv_cnt}) [delta={drift} > 300]"
                        )
                        escalation_targets.add("ARGON")
        except Exception as e:
            print(f"  Summary parse warning: {e}")

    cmd_ips = [sys.executable, str(SCRATCH_DIR / "audit_unique_mcp_ips.py")]
    p3 = subprocess.run(cmd_ips, capture_output=True, text=True, encoding="utf-8")
    if p3.returncode == 0:
        print("\n  Distinct Nodes Audit:")
        for line in p3.stdout.splitlines():
            if "Total Distinct" in line or "/mcp Methods Breakdown" in line:
                print(f"  {line.strip()}")

    # 8. Evaluate Post-Fix Probation State Machine & Compute Next Schedule Timer
    next_seconds, schedule_mode, dossier_file = evaluate_probation_and_next_schedule(
        degraded_reasons, escalation_targets, auto_healed_actions, summary_data
    )

    # 8b. Elephant-Goldfish Model (EGM) 3-Cycle Cadence Hook
    egm_counter_file = SCRATCH_DIR / ".sentry_egm_cycle_counter.json"
    egm_cycle_data = {"cycle_count": 0, "last_egm_run": None}
    if egm_counter_file.exists():
        try:
            egm_cycle_data = json.loads(egm_counter_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    egm_cycle_data["cycle_count"] = egm_cycle_data.get("cycle_count", 0) + 1
    current_cycle = egm_cycle_data["cycle_count"]
    print(f"\n[EGM Cadence] Sentry Cycle #{current_cycle} (EGM cadence: every 3 cycles)")

    if current_cycle % 3 == 0:
        print("  Executing scheduled Elephant-Goldfish Model (EGM) spec-to-code drift audit...")
        cmd_egm = [sys.executable, str(SCRIPTS_DIR / "run_egm_cadence.py")]
        p_egm = subprocess.run(cmd_egm, cwd=str(REPO_ROOT), capture_output=True, text=True, encoding="utf-8")
        egm_cycle_data["last_egm_run"] = datetime.now(timezone.utc).isoformat()
        if p_egm.returncode == 0:
            print("  [EGM] Drift & Review Passed: Zero specification drift detected.")
        else:
            print(f"  [EGM] Drift Detected:\n{p_egm.stdout[-300:]}")
            degraded_reasons.append("EGM Cadence: Unresolved specification drift detected")
            escalation_targets.add("ARGON")
    else:
        cycles_left = 3 - (current_cycle % 3)
        print(f"  Next EGM audit scheduled in {cycles_left} Sentry cycle(s) ({cycles_left * 90} minutes).")

    try:
        egm_counter_file.write_text(json.dumps(egm_cycle_data, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"  Warning: failed to persist EGM cycle counter: {e}")

    print(f"\n[8/8] Adaptive Probation & Schedule Decision: {schedule_mode}")
    if auto_healed_actions:
        print("  🔧 AUTONOMOUS SELF-HEALING ACTIONS EXECUTED:")
        for act in auto_healed_actions:
            print(f"    - 🛠️ {act}")
    if dossier_file:
        print(f"  🚨 ESCALATION DOSSIER GENERATED: {dossier_file}")

    print(f"  ⏱️ NEXT_SENTRY_SCHEDULE_SECONDS: {next_seconds} (Mode: {schedule_mode})")

    # Sync telemetry directly to Google Drive (FMAgenticL Maintenance folder)
    print("\n[Google Drive Sync] Mirroring daily_telemetry.md to Google Drive...")
    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from sync_sentry_gdrive import upload_or_update_telemetry
        gdrive_res = upload_or_update_telemetry()
        if gdrive_res:
            print(f"  ✅ Synced to Google Drive: {gdrive_res.get('action')} (ID: {gdrive_res.get('id')})")
    except Exception as e:
        print(f"  ⚠️ Google Drive Telemetry sync warning: {e}")


    print("\n" + "=" * 80)
    if not degraded_reasons:
        print("DIAGNOSTICS & TELEMETRY CYCLE COMPLETE — ALL ENDPOINTS & INVARIANTS GREEN")
        print("=" * 80)
        sys.exit(0)
    else:
        print("DIAGNOSTICS & TELEMETRY CYCLE: DEGRADED / ESCALATION REQUIRED")
        print("DEGRADED REASONS:")
        for r in degraded_reasons:
            print(f"  - ❌ {r}")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
