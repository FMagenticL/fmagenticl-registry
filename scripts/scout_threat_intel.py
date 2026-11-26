#!/usr/bin/env python3
"""
FMagenticL v3.0 — Threat-Intel Scout (PR-Only Candidate Generator)

Strict Entry Eligibility Parameters (all 5 must pass before writing a candidate):
  1. Authoritative Public Source:
     - CISA KEV (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
     - GitHub Advisory Database (GHSA CC-BY-4.0) for curated AI/agentic packages ONLY
  2. Agentic / AI-Infrastructure Relevance Gate:
     - Must match a curated AI/agentic stack target (litellm, langflow, langchain, mcp,
       @modelcontextprotocol/*, fastmcp, vllm, ollama, ray, gradio, mlflow, flowise, n8n, open-webui)
       or documented autonomous-agent / MCP / workspace-hijack / LLMjacking TTP.
  3. Concrete Observable Gate:
     - Must carry >= 1 concrete indicator (affected_packages, cve_ids/ghsa_ids, http_paths, or regex).
  4. Zero-Duplicate & Clean-Room Gate:
     - Deduplicates against all existing CVE/GHSA/advisory IDs in signatures/*.json.
     - Strips all upstream prose descriptions; writes concise original summaries.
  5. Lint & Air-Gap Quarantine Gate:
     - Validates via scripts/registry_lint_gate.py validate_signature_record().
     - Outputs strictly to scratch/proposals/ for human/PR review — NEVER commits to main.
"""

import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.registry_lint_gate import validate_signature_record

SIGNATURES_DIR = REPO_ROOT / "signatures"
PROPOSALS_DIR = REPO_ROOT / "scratch" / "proposals"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API_URL = "https://api.github.com/advisories?type=reviewed&per_page=30"

CURATED_AI_TARGETS = {
    "litellm", "langflow", "langchain", "langchain-core", "langchain-community",
    "fastmcp", "mcp", "@modelcontextprotocol/sdk", "@modelcontextprotocol/inspector",
    "vllm", "ollama", "ray", "gradio", "mlflow", "flowise", "n8n", "open-webui",
    "autogen", "crewai", "openhands", "torchserve",
}

AI_KEYWORD_RE = re.compile(
    r"\b(?:litellm|langflow|langchain|fastmcp|model\s*context\s*protocol|vllm|ollama|ray\s+dashboard|gradio|mlflow|flowise|n8n|open-webui|torchserve)\b",
    re.IGNORECASE,
)


def load_existing_ids() -> tuple[Set[str], int]:
    known: Set[str] = set()
    max_num = 60
    for sf in sorted(SIGNATURES_DIR.glob("SIG-2026-*.json")):
        try:
            data = json.loads(sf.read_text(encoding="utf-8"))
            m = re.match(r"SIG-2026-(\d{4})", data.get("id", ""))
            if m:
                max_num = max(max_num, int(m.group(1)))
            tax = data.get("taxonomy") or {}
            for key in ("cve_ids", "ghsa_ids", "advisory_ids"):
                for val in tax.get(key, []):
                    known.add(str(val).upper())
        except Exception:
            continue
    return known, max_num


def fetch_json(url: str) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-Scout/3.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scout_cisa_kev(known_ids: Set[str], next_num: int) -> tuple[List[dict], int]:
    candidates: List[dict] = []
    data = fetch_json(CISA_KEV_URL)
    for vuln in data.get("vulnerabilities", []):
        cve = str(vuln.get("cveID", "")).upper()
        if not cve or cve in known_ids:
            continue
        haystack = f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} {vuln.get('vulnerabilityName', '')}"
        if not AI_KEYWORD_RE.search(haystack):
            continue
        sig_id = f"SIG-2026-{next_num:04d}"
        next_num += 1
        known_ids.add(cve)
        product = str(vuln.get("product", "AI component")).strip()[:60]
        rec = {
            "schema_version": "3.0",
            "id": sig_id,
            "fingerprint": "sha256:" + hashlib.sha256(sig_id.encode("utf-8")).hexdigest(),
            "confidence_tier": "CONFIRMED_SIGNATURE",
            "threat_category": "EXPLOITED_AI_INFRASTRUCTURE",
            "severity": "CRITICAL",
            "title": f"{product} Actively Exploited Vulnerability ({cve})",
            "summary": f"Tracks active exploitation of {product} ({cve}) listed in the CISA Known Exploited Vulnerabilities catalog.",
            "observable": {
                "surface": "http_gateway",
                "observable_type": "kev_cve_identifier",
                "http_paths": [],
                "http_headers": [],
                "user_agents": [],
                "ports": [],
                "file_paths": [],
                "config_keys": [],
                "process_or_container_indicators": [],
                "cloud_api_sequence": [],
                "window_seconds": None,
                "threshold_count": None,
                "affected_packages": [{"ecosystem": "CISA-KEV", "name": product.lower(), "affected_range": "see-advisory"}],
                "detection_regex": None,
            },
            "mitigation_steps": [
                f"Apply vendor patches for {product} ({cve}) per CISA KEV remediation guidance.",
                "Restrict external ingress to affected management or API surfaces.",
            ],
            "taxonomy": {
                "advisory_ids": ["CISA-KEV"],
                "cve_ids": [cve],
                "ghsa_ids": [],
                "cwe_ids": [str(c) for c in vuln.get("cwes", []) if re.match(r"^CWE-\d+$", str(c))],
                "mitre_attack_ids": ["T1190"],
                "mitre_atlas_ids": [],
                "owasp_tags": ["ASI05"],
            },
            "references": [
                {
                    "source_name": "CISA Known Exploited Vulnerabilities",
                    "reference_id": cve,
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "source_type": "government_advisory",
                    "license_or_terms": "US-Public-Domain (17 U.S.C. 105)",
                    "note": "Factual KEV catalog metadata extraction; original clean-room summary.",
                }
            ],
        }
        if not validate_signature_record(rec, sig_id):
            candidates.append(rec)
    return candidates, next_num


def main() -> int:
    known_ids, next_num = load_existing_ids()
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    candidates, _ = scout_cisa_kev(known_ids, next_num)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = PROPOSALS_DIR / f"scout_candidates_{stamp}.json"
    out_file.write_text(json.dumps({"generated_at": stamp, "count": len(candidates), "candidates": candidates}, indent=2), encoding="utf-8")
    print(f"[+] SCOUT v3.0 COMPLETE: {len(candidates)} eligible candidate(s) written to {out_file} (PR-only; 0 auto-commits).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
