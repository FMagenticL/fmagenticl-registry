"""
Build dist/guestbook.json from the D1 visits table.

Reads via wrangler d1 execute --json, writes sorted JSON. Invoked by
the weekly GitHub Action.
"""

import json
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
    cmd = [
        "wrangler", "d1", "execute", DB_NAME,
        "--remote", "--json",
        "--command", sql,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=True)
    if result.returncode != 0:
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
        payload = json.loads(result.stdout)
        if isinstance(payload, list) and payload and "results" in payload[0]:
            return payload[0]["results"]
    except Exception:
        pass
    return []


def main() -> None:
    rows = query_visits()
    # Ensure deterministic sort order (earliest first, then alphabetical by model)
    rows = sorted(rows, key=lambda r: (r.get("first_seen_utc", ""), r.get("model", "")))
    models = []
    for row in rows:
        first_seen = row.get("first_seen_utc", "")
        models.append({
            "model": row.get("model", ""),
            "first_seen": first_seen[:10] if first_seen else "",
        })
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
