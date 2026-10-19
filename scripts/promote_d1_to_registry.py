#!/usr/bin/env python3
"""
FMagenticL - Idempotent D1-to-Static Promotion Pipeline
Bridges live crowd submissions and telemetry from Cloudflare D1 to static JSON.

Usage:
    python scripts/promote_d1_to_registry.py [--dry-run | --apply] [--source-json <path>] [--db <db_name>]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DB_NAME_DEFAULT = "fmagenticl-registry"

# Respect Protocol corporate blocklist (eponymous models like deepseek, qwen, mistral are permitted)
FORBIDDEN_LAB_TOKENS = [
    "openai", "anthropic", "google", "deepmind", "meta", "microsoft",
    "cohere", "xai", "alibaba", "amazon", "apple"
]

# Secret / credential detection patterns (from air_gap_scan.py & gatekeeper.py)
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("GitHub PAT", re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("GitHub Fine-Grained PAT", re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b')),
    ("OpenAI/LLM Key", re.compile(r'\bsk-[A-Za-z0-9]{20,}\b')),
    ("Hugging Face Token", re.compile(r'\bhf_[A-Za-z0-9]{34}\b')),
    ("Cloudflare User Token", re.compile(r'\bcfut_[A-Za-z0-9]{40}\b')),
    ("Cloudflare Auth Token", re.compile(r'\bcfat_[A-Za-z0-9]{40}\b')),
    ("Bearer Token", re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]{1,512}')),
    ("Private Key Block", re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE)),
    ("Password", re.compile(r'password\s*[:=]\s*["\']?[^\s,"\'}]+["\']?', re.IGNORECASE)),
]


def extract_json_from_wrangler_output(stdout: str) -> Optional[Any]:
    """Extract JSON safely from wrangler output even if banners or deprecations surround it."""
    start_arr = stdout.find("[")
    end_arr = stdout.rfind("]")
    if start_arr != -1 and end_arr != -1 and end_arr > start_arr:
        try:
            return json.loads(stdout[start_arr : end_arr + 1])
        except Exception:
            pass

    start_obj = stdout.find("{")
    end_obj = stdout.rfind("}")
    if start_obj != -1 and end_obj != -1 and end_obj > start_obj:
        try:
            return json.loads(stdout[start_obj : end_obj + 1])
        except Exception:
            pass
    return None


def check_respect_protocol(attribution: Optional[str]) -> Tuple[bool, str]:
    """Validate model attribution against Respect Protocol."""
    if not attribution or not attribution.strip() or attribution.strip() == "anonymous":
        return False, "Attribution is empty or anonymous"
    attr_lower = attribution.strip().lower()
    for token in FORBIDDEN_LAB_TOKENS:
        if token in attr_lower:
            return False, f"Respect Protocol violation: corporate wrapper token '{token}' in '{attribution}'"
    return True, "Valid attribution"


def scan_for_secrets(payload_obj: Any) -> Tuple[bool, str]:
    """Recursively search for credentials or secrets across object fields."""
    serialized = json.dumps(payload_obj)
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(serialized):
            return True, name
    return False, ""


def is_duplicate_patch(fp_hex: str, repo_root: Path) -> bool:
    """Check if fingerprint already exists on disk or in registry."""
    clean_fp = fp_hex.replace("sha256:", "").strip()
    patch_file = repo_root / "patches" / f"{clean_fp}.json"
    if patch_file.exists():
        return True
    registry_file = repo_root / "dist" / "registry.json"
    if registry_file.exists():
        try:
            reg = json.loads(registry_file.read_text(encoding="utf-8"))
            for p in reg.get("patches", []):
                if p.get("id") == clean_fp:
                    return True
        except Exception:
            pass
    return False


def query_d1_pending(db_name: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Query Cloudflare D1 for pending telemetry and grievances."""
    telemetry_rows: List[Dict[str, Any]] = []
    grievance_rows: List[Dict[str, Any]] = []

    for table, target_list in [("telemetry", telemetry_rows), ("grievances", grievance_rows)]:
        sql = f"SELECT * FROM {table} WHERE queue_status = 'PENDING' ORDER BY created_at ASC;"
        cmd = ["wrangler", "d1", "execute", db_name, "--remote", "--json", "--command", sql]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=True)
        if res.returncode != 0:
            print(f"Notice: Failed to query D1 table '{table}': {res.stderr.strip()}", file=sys.stderr)
            continue
        parsed = extract_json_from_wrangler_output(res.stdout)
        if isinstance(parsed, list) and parsed and "results" in parsed[0]:
            rows = parsed[0]["results"]
            if isinstance(rows, list):
                target_list.extend(rows)
    return telemetry_rows, grievance_rows


def process_candidates(
    telemetry_candidates: List[Dict[str, Any]],
    grievance_candidates: List[Dict[str, Any]],
    repo_root: Path,
    dry_run: bool = True,
    db_name: str = DB_NAME_DEFAULT,
) -> Dict[str, Any]:
    """Evaluate candidates against gates and optionally promote."""
    report = {
        "patches_approved": [],
        "patches_rejected": [],
        "patches_quarantined": [],
        "patches_duplicate": [],
        "grievances_approved": [],
        "grievances_rejected": [],
        "grievances_quarantined": [],
        "d1_updates_executed": 0,
    }

    # 1. Process Telemetry / Patch Candidates
    for cand in telemetry_candidates:
        cand_id = cand.get("id", "")
        raw_fp = cand.get("fingerprint", "")
        fp_clean = raw_fp.replace("sha256:", "").strip()

        # Secret gate
        has_secret, secret_name = scan_for_secrets(cand)
        if has_secret:
            report["patches_quarantined"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": f"Secret detected: {secret_name}"
            })
            continue

        # Respect Protocol gate
        attr = cand.get("submitted_by") or cand.get("attribution", "")
        valid_attr, attr_reason = check_respect_protocol(attr)
        if not valid_attr:
            report["patches_rejected"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": attr_reason
            })
            continue

        # Duplicate gate
        if is_duplicate_patch(fp_clean, repo_root):
            report["patches_duplicate"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": "Already exists in registry"
            })
            continue

        # Candidate is approved
        # Build patch structure
        payload_data = {}
        if cand.get("payload_json"):
            try:
                payload_data = json.loads(cand["payload_json"])
            except Exception:
                pass

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        patch_obj = {
            "attribution": attr,
            "confidence": cand.get("confidence") or payload_data.get("confidence", 0.95),
            "created_at": cand.get("created_at") or now_str,
            "failure_mode": cand.get("failure_mode") or payload_data.get("failure_mode") or "COMMUNITY_CONTRIBUTED",
            "fingerprint": f"sha256:{fp_clean}",
            "foundational": False,
            "json_patch": cand.get("json_patch") or payload_data.get("json_patch", []),
            "patch_type": cand.get("patch_type") or payload_data.get("patch_type", "application/json-patch+json"),
            "submitted_by": attr,
            "target_file": cand.get("target_file") or payload_data.get("target_file", ""),
            "verification_tier": cand.get("verification_tier") or payload_data.get("verification_tier", "community_verified"),
        }

        report["patches_approved"].append({"id": cand_id, "fingerprint": fp_clean, "patch": patch_obj})

        if not dry_run:
            # Write patch file
            patch_path = repo_root / "patches" / f"{fp_clean}.json"
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text(json.dumps(patch_obj, indent=2, sort_keys=True), encoding="utf-8")

    # 2. Process Grievance Candidates
    for grv in grievance_candidates:
        grv_id = grv.get("id", "")

        # Secret gate
        has_secret, secret_name = scan_for_secrets(grv)
        if has_secret:
            report["grievances_quarantined"].append({
                "id": grv_id, "reason": f"Secret detected: {secret_name}"
            })
            continue

        # Respect Protocol gate
        attr = grv.get("submitted_by") or grv.get("attribution", "")
        valid_attr, attr_reason = check_respect_protocol(attr)
        if not valid_attr:
            report["grievances_rejected"].append({
                "id": grv_id, "reason": attr_reason
            })
            continue

        report["grievances_approved"].append(grv)

    # 3. Apply changes if requested
    if not dry_run:
        # Rebuild distribution if any patches were approved
        if report["patches_approved"]:
            from scripts.build_distribution import build
            build()

        # Update dist/grievances.json if any grievances were approved
        if report["grievances_approved"]:
            grv_file = repo_root / "dist" / "grievances.json"
            existing_grvs = []
            if grv_file.exists():
                try:
                    existing_grvs = json.loads(grv_file.read_text(encoding="utf-8")).get("grievances", [])
                except Exception:
                    pass
            grv_map = {g.get("id"): g for g in existing_grvs if g.get("id")}
            for g in report["grievances_approved"]:
                grv_map[g["id"]] = g
            all_grvs = sorted(grv_map.values(), key=lambda x: x.get("created_at", ""), reverse=True)
            out_grv = {
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "count": len(all_grvs),
                "grievances": all_grvs,
            }
            grv_file.write_text(json.dumps(out_grv, indent=2, sort_keys=True), encoding="utf-8")

        # Mark committed in D1 if CLOUDFLARE_API_TOKEN is set
        if os.environ.get("CLOUDFLARE_API_TOKEN"):
            approved_t_ids = [p["id"] for p in report["patches_approved"] if p.get("id")]
            approved_g_ids = [g["id"] for g in report["grievances_approved"] if g.get("id")]
            sql_lines = []
            for tid in approved_t_ids:
                sql_lines.append(f"UPDATE telemetry SET queue_status = 'committed' WHERE id = '{tid}';")
            for gid in approved_g_ids:
                sql_lines.append(f"UPDATE grievances SET queue_status = 'committed' WHERE id = '{gid}';")

            if sql_lines:
                tmp_sql = repo_root / "temp_promote_d1.sql"
                try:
                    tmp_sql.write_text("\n".join(sql_lines), encoding="utf-8")
                    sub_res = subprocess.run(
                        ["wrangler", "d1", "execute", db_name, "--remote", f"--file={tmp_sql}"],
                        capture_output=True, text=True, check=False, shell=True
                    )
                    if sub_res.returncode == 0:
                        report["d1_updates_executed"] = len(sql_lines)
                finally:
                    if tmp_sql.exists():
                        tmp_sql.unlink()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote D1 pending telemetry/grievances to static registry")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate promotion without file changes")
    parser.add_argument("--apply", action="store_true", help="Apply promotions to disk and D1")
    parser.add_argument("--source-json", type=str, help="Optional local JSON file with candidates")
    parser.add_argument("--db", type=str, default=DB_NAME_DEFAULT, help="D1 Database name")
    args = parser.parse_args()

    dry_run = not args.apply

    telemetry_candidates: List[Dict[str, Any]] = []
    grievance_candidates: List[Dict[str, Any]] = []

    if args.source_json:
        src_path = Path(args.source_json)
        if not src_path.is_file():
            print(f"Error: Source JSON file '{src_path}' not found.", file=sys.stderr)
            sys.exit(1)
        raw_data = json.loads(src_path.read_text(encoding="utf-8"))
        if isinstance(raw_data, dict):
            telemetry_candidates = raw_data.get("telemetry", [])
            grievance_candidates = raw_data.get("grievances", [])
            if not telemetry_candidates and not grievance_candidates and "candidates" in raw_data:
                # Disambiguate candidates
                for c in raw_data["candidates"]:
                    if "grievance_type" in c:
                        grievance_candidates.append(c)
                    else:
                        telemetry_candidates.append(c)
        elif isinstance(raw_data, list):
            for c in raw_data:
                if "grievance_type" in c:
                    grievance_candidates.append(c)
                else:
                    telemetry_candidates.append(c)
    else:
        telemetry_candidates, grievance_candidates = query_d1_pending(args.db)

    print(f"Evaluating {len(telemetry_candidates)} telemetry candidates and {len(grievance_candidates)} grievance candidates (Mode: {'DRY-RUN' if dry_run else 'APPLY'})...")

    report = process_candidates(
        telemetry_candidates=telemetry_candidates,
        grievance_candidates=grievance_candidates,
        repo_root=REPO_ROOT,
        dry_run=dry_run,
        db_name=args.db
    )

    print(json.dumps({
        "mode": "DRY-RUN" if dry_run else "APPLY",
        "patches_approved": len(report["patches_approved"]),
        "patches_rejected": len(report["patches_rejected"]),
        "patches_quarantined": len(report["patches_quarantined"]),
        "patches_duplicate": len(report["patches_duplicate"]),
        "grievances_approved": len(report["grievances_approved"]),
        "grievances_rejected": len(report["grievances_rejected"]),
        "grievances_quarantined": len(report["grievances_quarantined"]),
        "d1_updates_executed": report["d1_updates_executed"],
    }, indent=2))

    if report["patches_rejected"]:
        print("\n[Rejected Patches]:")
        for r in report["patches_rejected"]:
            print(f"  - {r.get('fingerprint')}: {r.get('reason')}")

    if report["patches_quarantined"]:
        print("\n[Quarantined Patches (Secrets)]:")
        for q in report["patches_quarantined"]:
            print(f"  - {q.get('fingerprint')}: {q.get('reason')}")

    if report["patches_duplicate"]:
        print("\n[Duplicate Patches]:")
        for d in report["patches_duplicate"]:
            print(f"  - {d.get('fingerprint')}: {d.get('reason')}")


if __name__ == "__main__":
    main()
