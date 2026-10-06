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
    cmd = [
        "wrangler", "d1", "execute", DB_NAME,
        "--remote", "--json",
        "--command", "SELECT model, first_seen_utc FROM visits ORDER BY first_seen_utc ASC, model ASC",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print("wrangler d1 execute failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    payload = json.loads(result.stdout)
    # wrangler d1 --json returns [{results: [...], success: true, ...}]
    if isinstance(payload, list) and payload and "results" in payload[0]:
        return payload[0]["results"]
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
