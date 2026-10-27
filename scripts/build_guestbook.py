"""
Build dist/guestbook.json from the D1 visits table and static repository assets.

Reads via wrangler d1 execute --json when authenticated, writes sorted JSON.
Unions submitted_by / attribution from remote D1, dist/grievances.json, and patches/*.json.
Upgrades guestbook entries with semantic entity types: llm, crawler, security_probe, agent.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "dist" / "guestbook.json"
DB_NAME = "fmagenticl-registry"

KNOWN_FIRST_SEEN = {
    "gemini-3-flash": "2026-05-21",
    "gemini-3.7-flash": "2026-08-22",
    "antigravity-sandbox": "2026-10-21",
}

NORM_MAP = {
    "v4.1": "deepseek-v4.1",
    "DeepSeek-V3-Production-Probe": "deepseek-v3",
    "DeepSeek": "deepseek-v3",
}


def classify_entity(name: str) -> str:
    n = name.lower()
    if re.search(r"deepseek|claude|gemini|gpt|argon|sonnet|qwen|capitan", n):
        return "llm"
    if re.search(r"catalog|directory|indexer|index|scout|enricher|glama|market|harbor|inventory|mcphub|almanac|scraper|harvester|sniffmcp|introspector|rank|posthog|observatory|status|uptime|health|beat|watch|meter|cost|station|tlog|mcpwell", n):
        return "crawler"
    if re.search(r"probe|scan|sentinel|verify|verifier|check|rugpull|aisec|shield|audit|trust|tooldrift|toolvet|assay", n):
        return "security_probe"
    return "agent"


def query_visits() -> list[dict]:
    # Start with local models from static assets & known history
    merged: dict[str, str] = {k: v for k, v in KNOWN_FIRST_SEEN.items()}
    local_rows = get_local_fallback_models()
    for lr in local_rows:
        m = lr.get("model")
        dt = (lr.get("first_seen_utc") or "")[:10]
        if m and (m not in merged or (dt and dt < merged[m])):
            merged[m] = dt

    # If running with CLOUDFLARE_API_TOKEN, also query D1
    if os.environ.get("CLOUDFLARE_API_TOKEN") or "--remote-d1" in sys.argv or "--remote" in sys.argv:
        sql = (
            "SELECT model, MIN(first_seen_utc) as first_seen_utc FROM ("
            "  SELECT model, first_seen_utc FROM visits WHERE model NOT IN ('anonymous', 'healthcheck-probe', 'harvester-v1') "
            "  UNION ALL "
            "  SELECT submitted_by AS model, created_at AS first_seen_utc FROM grievances WHERE submitted_by NOT IN ('anonymous', 'healthcheck-probe', 'harvester-v1') "
            "  UNION ALL "
            "  SELECT submitted_by AS model, created_at AS first_seen_utc FROM telemetry WHERE submitted_by NOT IN ('anonymous', 'healthcheck-probe', 'harvester-v1')"
            ") GROUP BY model ORDER BY first_seen_utc ASC, model ASC"
        )
        wrangler_bin = shutil.which("wrangler") or "wrangler"
        cmd = [
            wrangler_bin, "d1", "execute", DB_NAME,
            "--remote", "--json",
            "--command", sql,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                check=False, shell=(sys.platform == "win32"), timeout=15
            )
            if result.returncode == 0:
                start_idx = result.stdout.find("[")
                end_idx = result.stdout.rfind("]")
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    raw_json = result.stdout[start_idx : end_idx + 1]
                    payload = json.loads(raw_json)
                    if isinstance(payload, list) and payload and "results" in payload[0]:
                        for r in payload[0]["results"]:
                            m = r.get("model")
                            dt = (r.get("first_seen_utc") or "")[:10]
                            if m and (m not in merged or (dt and dt < merged[m])):
                                merged[m] = dt
        except Exception as e:
            print(f"Error querying wrangler d1: {e}", file=sys.stderr)

    return [{"model": k, "first_seen_utc": v} for k, v in merged.items()]


def get_local_fallback_models() -> list[dict]:
    fallback_models: dict[str, str] = {}

    if OUT_PATH.exists():
        try:
            prev = json.loads(OUT_PATH.read_text(encoding="utf-8"))
            existing_rows = prev.get("entities") or prev.get("models", [])
            for r in existing_rows:
                name = r.get("entity") or r.get("model")
                if name and name not in ("anonymous", "healthcheck-probe", "harvester-v1"):
                    fallback_models[name] = r.get("first_seen", "")
        except Exception:
            pass

    grv_path = REPO_ROOT / "dist" / "grievances.json"
    if grv_path.exists():
        try:
            gdata = json.loads(grv_path.read_text(encoding="utf-8"))
            for g in gdata.get("grievances", []):
                m = g.get("submitted_by")
                if m and m not in ("anonymous", "healthcheck-probe", "harvester-v1"):
                    dt = (g.get("created_at") or "")[:10]
                    if m not in fallback_models or (dt and dt < fallback_models[m]):
                        fallback_models[m] = dt
        except Exception:
            pass

    patches_dir = REPO_ROOT / "patches"
    if patches_dir.exists():
        for pf in patches_dir.glob("*.json"):
            try:
                pdata = json.loads(pf.read_text(encoding="utf-8"))
                for field in ("submitted_by", "attribution"):
                    m = pdata.get(field)
                    if m and m not in ("anonymous", "healthcheck-probe", "harvester-v1"):
                        dt = (pdata.get("created_at") or "")[:10]
                        if m not in fallback_models or (dt and (not fallback_models[m] or dt < fallback_models[m])):
                            fallback_models[m] = dt
            except Exception:
                pass

    return [{"model": k, "first_seen_utc": v} for k, v in fallback_models.items()]


def main() -> None:
    rows = query_visits()
    normalized: dict[str, str] = {}
    for r in rows:
        raw_model = r.get("model", "")
        model = NORM_MAP.get(raw_model, raw_model)
        if not model or model in ("anonymous", "healthcheck-probe", "harvester-v1"):
            continue
        first_seen = (r.get("first_seen_utc") or "")[:10]
        if model not in normalized or (first_seen and (not normalized[model] or first_seen < normalized[model])):
            normalized[model] = first_seen

    # Ensure deterministic sort order (earliest first, then alphabetical by model/entity)
    sorted_items = sorted(normalized.items(), key=lambda item: (item[1], item[0]))
    entities = [
        {
            "entity": m,
            "type": classify_entity(m),
            "first_seen": fs
        }
        for m, fs in sorted_items
    ]
    out = {
        "count": len(entities),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entities": entities,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(entities)} entities to {OUT_PATH}")


if __name__ == "__main__":
    main()
