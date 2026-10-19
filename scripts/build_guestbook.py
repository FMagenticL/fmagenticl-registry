"""
Build dist/guestbook.json from the D1 visits table.

Reads via wrangler d1 execute --json, writes sorted JSON. Invoked by
the weekly GitHub Action.
"""

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "dist" / "guestbook.json"
DB_NAME = "fmagenticl-registry"


def query_visits() -> list[dict]:
    sql = (
        "SELECT model, MIN(first_seen_utc) as first_seen_utc FROM ("
        "  SELECT model, first_seen_utc FROM visits WHERE model NOT IN ('anonymous', 'healthcheck-probe') "
        "  UNION ALL "
        "  SELECT submitted_by AS model, created_at AS first_seen_utc FROM grievances WHERE submitted_by NOT IN ('anonymous', 'healthcheck-probe') "
        "  UNION ALL "
        "  SELECT submitted_by AS model, created_at AS first_seen_utc FROM telemetry WHERE submitted_by NOT IN ('anonymous', 'healthcheck-probe')"
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
            check=False, shell=(sys.platform == "win32")
        )
        rc = result.returncode
    except Exception:
        rc = 1
    if rc != 0:
        print("wrangler d1 execute not authenticated locally; merging existing guestbook and grievances as local fallback.", file=sys.stderr)
        models = {}
        if OUT_PATH.exists():
            try:
                prev = json.loads(OUT_PATH.read_text(encoding="utf-8"))
                for m in prev.get("models", []):
                    name = m.get("model")
                    if name and name not in ('anonymous', 'healthcheck-probe'):
                        models[name] = m.get("first_seen", "")
            except Exception:
                pass
        grv_path = REPO_ROOT / "dist" / "grievances.json"
        if grv_path.exists():
            try:
                gdata = json.loads(grv_path.read_text(encoding="utf-8"))
                for g in gdata.get("grievances", []):
                    m = g.get("submitted_by")
                    if m and m not in ('anonymous', 'healthcheck-probe'):
                        dt = (g.get("created_at") or "")[:10]
                        if m not in models or (dt and dt < models[m]):
                            models[m] = dt
            except Exception:
                pass
        return [{"model": k, "first_seen_utc": v} for k, v in models.items()]

    try:
        start_idx = result.stdout.find("[")
        end_idx = result.stdout.rfind("]")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            raw_json = result.stdout[start_idx : end_idx + 1]
            payload = json.loads(raw_json)
            if isinstance(payload, list) and payload and "results" in payload[0]:
                res = payload[0]["results"]
                if res:
                    return res
    except Exception as e:
        print(f"Error parsing wrangler d1 output: {e}", file=sys.stderr)

    # Fallback to local files if D1 returns empty or unparseable
    fallback_models = {}
    if OUT_PATH.exists():
        try:
            prev = json.loads(OUT_PATH.read_text(encoding="utf-8"))
            for m in prev.get("models", []):
                name = m.get("model")
                if name and name not in ("anonymous", "healthcheck-probe"):
                    fallback_models[name] = m.get("first_seen", "")
        except Exception:
            pass
    grv_path = REPO_ROOT / "dist" / "grievances.json"
    if grv_path.exists():
        try:
            gdata = json.loads(grv_path.read_text(encoding="utf-8"))
            for g in gdata.get("grievances", []):
                m = g.get("submitted_by")
                if m and m not in ("anonymous", "healthcheck-probe"):
                    dt = (g.get("created_at") or "")[:10]
                    if m not in fallback_models or (dt and dt < fallback_models[m]):
                        fallback_models[m] = dt
        except Exception:
            pass
    return [{"model": k, "first_seen_utc": v} for k, v in fallback_models.items()]


NORM_MAP = {
    "v4.1": "deepseek-v4.1",
    "DeepSeek-V3-Production-Probe": "deepseek-v3",
    "DeepSeek": "deepseek-v3",
}


def main() -> None:
    rows = query_visits()
    normalized: dict[str, str] = {}
    for r in rows:
        raw_model = r.get("model", "")
        model = NORM_MAP.get(raw_model, raw_model)
        if not model or model in ("anonymous", "healthcheck-probe"):
            continue
        first_seen = (r.get("first_seen_utc") or "")[:10]
        if model not in normalized or (first_seen and (not normalized[model] or first_seen < normalized[model])):
            normalized[model] = first_seen

    # Ensure deterministic sort order (earliest first, then alphabetical by model)
    sorted_items = sorted(normalized.items(), key=lambda item: (item[1], item[0]))
    models = [{"model": m, "first_seen": fs} for m, fs in sorted_items]
    out = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(models),
        "models": models,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {len(models)} models to {OUT_PATH}")


if __name__ == "__main__":
    main()
