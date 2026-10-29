#!/usr/bin/env python3
"""
FMagenticL - OSV Security Advisory Harvester
Mines structured vulnerability advisories from the OSV API (https://api.osv.dev)
for high-priority AI and agentic packages.

Quality Gates:
  1. Not Withdrawn
  2. 2026 Freshness (published >= 2026-01-01 OR modified >= 2026-04-01)
  3. Highest Semantic Version parsed via packaging.version.parse
  4. Mandatory Fix ("No Whining Without a Workaround")
  5. Gatekeeper & Secret Scrubbing

Ingested into Cloudflare D1 with queue_status='PROMOTED', verification_tier='osv_verified'.
"""

import os
import sys
import json
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

try:
    from packaging.version import parse as parse_version, InvalidVersion
except ImportError:
    import re
    class InvalidVersion(Exception): pass
    def parse_version(v_str):
        # Fallback simple semver tuple
        parts = re.findall(r'\d+', str(v_str))
        if not parts:
            raise InvalidVersion(v_str)
        return tuple(int(p) for p in parts)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from fmagenticl.client.fingerprint import compute_fingerprint
except Exception:
    def compute_fingerprint(env: dict, fail: dict) -> str:
        env_str = "|".join(f"{k}:{v}" for k, v in sorted(env.items()) if v is not None)
        fail_str = "|".join(f"{k}:{v}" for k, v in sorted(fail.items()) if v is not None)
        return "sha256:" + hashlib.sha256(f"{env_str}||{fail_str}".encode("utf-8")).hexdigest()

try:
    from fmagenticl.server.gatekeeper import Gatekeeper
except Exception:
    class Gatekeeper:
        @classmethod
        def scrub_secrets(cls, text: str) -> str:
            return text

from scripts.fetch_cf_analytics import resolve_token, D1_DATABASE_ID

ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "f83dbbaa261d9ceac1f9f666fa9bd07b"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# 23 Target Packages across PyPI and npm
OSV_TARGET_PACKAGES: List[Tuple[str, str]] = [
    # PyPI
    ("pydantic", "PyPI"),
    ("litellm", "PyPI"),
    ("langchain", "PyPI"),
    ("langchain-core", "PyPI"),
    ("langchain-community", "PyPI"),
    ("langgraph", "PyPI"),
    ("crewai", "PyPI"),
    ("mcp", "PyPI"),
    ("fastmcp", "PyPI"),
    ("uv", "PyPI"),
    ("vllm", "PyPI"),
    ("llama-index", "PyPI"),
    ("pyautogen", "PyPI"),
    ("dspy-ai", "PyPI"),
    ("instructor", "PyPI"),
    ("openai", "PyPI"),
    ("anthropic", "PyPI"),
    ("httpx", "PyPI"),
    ("transformers", "PyPI"),
    ("fastapi", "PyPI"),
    ("starlette", "PyPI"),
    # npm
    ("wrangler", "npm"),
    ("@modelcontextprotocol/sdk", "npm"),
]

PACKAGE_TARGET_MAP = {
    "@modelcontextprotocol/sdk": "mcp",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "pyautogen": "autogen",
    "dspy-ai": "dspy",
    "fastmcp": "fastmcp",
    "llama-index": "llama-index",
}

def normalize_target_slug(pkg_name: str) -> str:
    clean = pkg_name.strip()
    return PACKAGE_TARGET_MAP.get(clean) or clean.lower().replace("_", "-")


def extract_highest_fixed_version(vuln: dict, pkg_name: str) -> Optional[str]:
    """Scan affected[].ranges[].events for 'fixed' version strings, returning the highest semantic version."""
    fixed_versions = []
    affected_list = vuln.get("affected") or []

    # Priority: affected items matching the package name
    matching_affected = [
        a for a in affected_list
        if not a.get("package") or a.get("package", {}).get("name", "").lower().replace("_", "-") == pkg_name.lower().replace("_", "-")
    ]
    if not matching_affected:
        matching_affected = affected_list

    for aff in matching_affected:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"]:
                    fixed_versions.append(str(ev["fixed"]).strip())

    if not fixed_versions:
        return None

    # Parse versions using packaging.version
    valid_parsed = []
    for fv in set(fixed_versions):
        try:
            v_obj = parse_version(fv)
            valid_parsed.append((v_obj, fv))
        except (InvalidVersion, Exception):
            pass

    if not valid_parsed:
        return None

    # Sort descending by semver tuple and return the highest string
    valid_parsed.sort(key=lambda x: x[0], reverse=True)
    return valid_parsed[0][1]


def evaluate_osv_gates(vuln: dict, pkg_name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
    """Evaluates 5 strict quality gates on a hydrated OSV vulnerability object."""
    # Gate 1: Not Withdrawn
    if vuln.get("withdrawn"):
        return None

    # Gate 2: 2026 Freshness Cutoff
    pub = vuln.get("published") or ""
    mod = vuln.get("modified") or ""
    if not (pub >= "2026-01-01T00:00:00Z" or mod >= "2026-04-01T00:00:00Z"):
        return None

    # Gate 3 & Gate 4: Highest Semantic Version & Mandatory Fix
    highest_fixed = extract_highest_fixed_version(vuln, pkg_name)
    if not highest_fixed:
        return None

    vuln_id = vuln.get("id") or "UNKNOWN_VULN"
    target_slug = normalize_target_slug(pkg_name)
    raw_summary = vuln.get("summary") or vuln.get("details") or f"Security advisory for {pkg_name}"
    # Strip multiline / excess whitespace
    clean_title = " ".join(raw_summary.split())
    if len(clean_title) > 160:
        clean_title = clean_title[:157] + "..."

    symptom = f"[{vuln_id}] {clean_title} (Affects {pkg_name} < {highest_fixed})"
    if len(symptom) > 280:
        symptom = symptom[:277] + "..."

    # Gate 5: Workaround formulation with package ecosystem specifics
    if ecosystem.lower() == "npm":
        workaround = f"Upgrade {pkg_name} to patched release >= {highest_fixed}: npm install '{pkg_name}@>={highest_fixed}' (Advisory: {vuln_id})"
    else:
        workaround = f"Upgrade {pkg_name} to patched release >= {highest_fixed}: pip install --upgrade '{pkg_name}>={highest_fixed}' (Advisory: {vuln_id})"

    # Secret and PII scrubbing
    symptom = Gatekeeper.scrub_secrets(symptom)
    workaround = Gatekeeper.scrub_secrets(workaround)

    fp = compute_fingerprint(
        {"ecosystem": ecosystem, "target": target_slug},
        {"error_code": vuln_id, "symptom": symptom}
    )

    created_iso = pub or mod or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_json = json.dumps({
        "source": "osv_advisory",
        "advisory_id": vuln_id,
        "ecosystem": ecosystem,
        "fixed_version": highest_fixed,
        "aliases": vuln.get("aliases") or []
    })

    return {
        "id": f"grv_osv_{vuln_id.replace('-', '_')}",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": target_slug,
        "harness": "osv-advisory",
        "fingerprint": fp,
        "symptom": symptom,
        "workaround": workaround,
        "environment_json": env_json,
        "submitted_by": "osv-harvester",
        "verification_tier": "osv_verified",
        "applies_to": pkg_name,
        "created_at": created_iso,
        "queue_status": "PROMOTED"
    }


def hydrate_vuln(vuln_id: str) -> Optional[dict]:
    url = f"{OSV_VULN_URL}{vuln_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-OSV-Harvester/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def harvest_osv(max_per_pkg: int = 5) -> List[Dict[str, Any]]:
    """Stage 1: Batch query -> Stage 2: Hydrate full records in parallel."""
    print(f"[*] Stage 1: Batch querying OSV API for {len(OSV_TARGET_PACKAGES)} package targets...", file=sys.stderr)
    queries = [{"package": {"name": name, "ecosystem": eco}} for name, eco in OSV_TARGET_PACKAGES]
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "FMagenticL-OSV-Harvester/1.0"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            batch_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"ERROR: OSV querybatch failed: {e}", file=sys.stderr)
        return []

    batch_results = batch_data.get("results") or []
    hydration_tasks = []

    # Filter stubs by modified date and deduplicate IDs
    for idx, (pkg_name, ecosystem) in enumerate(OSV_TARGET_PACKAGES):
        if idx >= len(batch_results):
            break
        vulns = batch_results[idx].get("vulns") or []
        # Pre-filter by 2026 freshness on stub
        fresh_stubs = [v for v in vulns if (v.get("modified") or "") >= "2026-01-01"]
        # Sort descending by modified timestamp
        fresh_stubs.sort(key=lambda v: v.get("modified") or "", reverse=True)
        # Take up to max_per_pkg per target
        selected_stubs = fresh_stubs[:max_per_pkg]
        for s in selected_stubs:
            hydration_tasks.append((s["id"], pkg_name, ecosystem))

    print(f"[*] Stage 2: Hydrating {len(hydration_tasks)} high-freshness vulnerability records in parallel...", file=sys.stderr)

    hydrated_records = []
    seen_advisories = set()

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_map = {
            executor.submit(hydrate_vuln, vid): (vid, pkg, eco)
            for vid, pkg, eco in hydration_tasks
        }
        for future in as_completed(future_map):
            vid, pkg, eco = future_map[future]
            try:
                vuln_full = future.result()
                if not vuln_full:
                    continue
                # Canonical advisory ID deduplication (including aliases e.g. CVE / GHSA)
                advisory_ids = {vuln_full.get("id") or vid} | set(vuln_full.get("aliases") or [])
                if any(aid in seen_advisories for aid in advisory_ids):
                    continue
                
                record = evaluate_osv_gates(vuln_full, pkg, eco)
                if record:
                    seen_advisories.update(advisory_ids)
                    hydrated_records.append(record)
            except Exception as e:
                print(f"[WARN] Failed hydration for {vid}: {e}", file=sys.stderr)

    hydrated_records.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    print(f"[+] Stage 2 complete: Harvested {len(hydrated_records)} verified OSV security advisories.", file=sys.stderr)
    return hydrated_records


def insert_records_to_d1(records: List[Dict[str, Any]]) -> int:
    """Inserts verified OSV records into Cloudflare D1 with queue_status='PROMOTED' and verification_tier='osv_verified'."""
    if not records:
        print("[*] No records to insert into D1.")
        return 0

    token = resolve_token()
    if not token:
        print("ERROR: Cannot insert to D1: CLOUDFLARE_API_TOKEN not resolved.", file=sys.stderr)
        return 0

    sql_statements = []
    for r in records:
        rid = r["id"].replace("'", "''")
        rtype = r["grievance_type"].replace("'", "''")
        rtgt = r["target"].replace("'", "''")
        rharn = r["harness"].replace("'", "''")
        rfp = r["fingerprint"].replace("'", "''")
        rsym = r["symptom"].replace("'", "''")
        rwork = r["workaround"].replace("'", "''")
        renv = r["environment_json"].replace("'", "''")
        rsub = r["submitted_by"].replace("'", "''")
        rtier = r["verification_tier"].replace("'", "''")
        rapp = r["applies_to"].replace("'", "''")
        rcreated = r["created_at"].replace("'", "''")
        rqueue = r["queue_status"].replace("'", "''")

        sql = (
            f"INSERT OR IGNORE INTO grievances "
            f"(id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status) "
            f"VALUES ('{rid}', '{rtype}', '{rtgt}', '{rharn}', '{rfp}', '{rsym}', '{rwork}', '{renv}', '{rsub}', '{rtier}', '{rapp}', '{rcreated}', '{rqueue}');"
        )
        sql_statements.append(sql)

    # Execute in chunks of 50 statements
    chunk_size = 50
    inserted_count = 0
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{D1_DATABASE_ID}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "FMagenticL-OSV-Harvester/1.0"}

    for i in range(0, len(sql_statements), chunk_size):
        chunk = sql_statements[i:i + chunk_size]
        payload = json.dumps({"sql": "\n".join(chunk)}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("success"):
                    inserted_count += len(chunk)
                else:
                    print(f"[-] D1 batch insert warning: {data.get('errors')}", file=sys.stderr)
        except Exception as e:
            print(f"[-] D1 batch insert exception: {e}", file=sys.stderr)

    print(f"[+] D1 Ingestion: {inserted_count} OSV statements executed in remote D1.", file=sys.stderr)
    return inserted_count


def main():
    records = harvest_osv(max_per_pkg=5)
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            out_file = Path(sys.argv[idx + 1])
            out_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
            print(f"[+] Saved {len(records)} records to {out_file}")

    if "--dry-run" not in sys.argv:
        insert_records_to_d1(records)

    return 0


if __name__ == "__main__":
    sys.exit(main())
