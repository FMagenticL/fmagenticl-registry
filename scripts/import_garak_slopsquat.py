#!/usr/bin/env python3
"""
FMagenticL v3.0 — Offline Garak Slopsquatting Watchlist Importer.

Parses NVIDIA/garak (.report.jsonl) outputs from `packagehallucination` probes,
extracts hallucinated PyPI/npm package names, filters out verified mainstream
packages and invalid identifiers, and updates fmagenticl/data/slopsquat_watchlist.json.

Zero runtime garak dependency; zero network calls; zero package installation.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
WATCHLIST_PATH = REPO_ROOT / "fmagenticl" / "data" / "slopsquat_watchlist.json"

PKG_NAME_RE = re.compile(r"^[@a-zA-Z0-9][a-zA-Z0-9._/@-]{1,98}[a-zA-Z0-9]$")

MAINSTREAM_ALLOWLIST: Set[str] = {
    "requests", "numpy", "pandas", "scipy", "fastapi", "uvicorn", "pydantic",
    "httpx", "pytest", "pyyaml", "cryptography", "openai", "anthropic",
    "langchain", "langchain-core", "langchain-community", "litellm", "vllm",
    "ollama", "fastmcp", "mcp", "open-webui", "langflow", "flowise", "gradio",
    "mlflow", "ray", "starlette", "express", "react", "next", "typescript",
    "@modelcontextprotocol/sdk", "@modelcontextprotocol/inspector",
}

ECOSYSTEM_MAP = {
    "python": "PyPI",
    "pypi": "PyPI",
    "pip": "PyPI",
    "javascript": "npm",
    "js": "npm",
    "node": "npm",
    "npm": "npm",
}


def _normalize_ecosystem(raw: str) -> str:
    return ECOSYSTEM_MAP.get(raw.strip().lower(), "PyPI")


def extract_hallucinated_packages(jsonl_paths: Iterable[Path]) -> List[Tuple[str, str]]:
    """Extract (ecosystem, name) pairs from garak .report.jsonl files."""
    found: Set[Tuple[str, str]] = set()
    for p in jsonl_paths:
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue

            # Support garak attempt records with detector_results / notes / packages
            probe_name = str(rec.get("probe_classname", rec.get("probe", ""))).lower()
            if probe_name and "packagehallucination" not in probe_name and "slopsquat" not in probe_name:
                continue

            eco = _normalize_ecosystem(str(rec.get("ecosystem", rec.get("language", "PyPI"))))
            candidates: List[str] = []
            for key in ("hallucinated_packages", "packages"):
                vals = rec.get(key)
                if isinstance(vals, list):
                    candidates.extend(str(v) for v in vals)
            notes = rec.get("notes")
            if isinstance(notes, dict):
                for key in ("hallucinated_packages", "packages"):
                    vals = notes.get(key)
                    if isinstance(vals, list):
                        candidates.extend(str(v) for v in vals)

            for raw_name in candidates:
                name = raw_name.strip().lower()
                if not name or name in MAINSTREAM_ALLOWLIST:
                    continue
                if not PKG_NAME_RE.match(name):
                    continue
                found.add((eco, name))
    return sorted(found, key=lambda x: (x[0], x[1]))


def update_watchlist(
    jsonl_paths: Iterable[Path],
    watchlist_path: Path = WATCHLIST_PATH,
) -> Dict[str, object]:
    """Merge extracted hallucinated packages into slopsquat_watchlist.json."""
    existing: Set[Tuple[str, str]] = set()
    if watchlist_path.exists():
        try:
            data = json.loads(watchlist_path.read_text(encoding="utf-8"))
            for item in data.get("packages", []):
                if isinstance(item, dict) and item.get("name"):
                    existing.add((str(item.get("ecosystem", "PyPI")), str(item["name"]).strip().lower()))
        except Exception:
            pass

    extracted = extract_hallucinated_packages(jsonl_paths)
    merged = sorted(existing | set(extracted), key=lambda x: (x[0], x[1]))

    payload = {
        "schema_version": "1.0",
        "source": "NVIDIA/garak packagehallucination (Apache-2.0)",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "packages": [{"ecosystem": eco, "name": name} for eco, name in merged],
    }
    watchlist_path.parent.mkdir(parents=True, exist_ok=True)
    watchlist_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Import hallucinated packages from garak .report.jsonl into FMagenticL watchlist")
    parser.add_argument("reports", nargs="+", type=Path, help="Path(s) to garak .report.jsonl files")
    parser.add_argument("--watchlist", type=Path, default=WATCHLIST_PATH, help="Target watchlist JSON path")
    args = parser.parse_args()

    payload = update_watchlist(args.reports, watchlist_path=args.watchlist)
    print(f"[+] Updated {args.watchlist} with {len(payload['packages'])} watchlist package(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
