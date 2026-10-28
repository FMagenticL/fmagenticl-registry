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
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DB_NAME_DEFAULT = "fmagenticl-registry"

# Historical Respect Protocol blocklist. Retained for reference only.
# Phase 10.2 Policy: Open self-identification — this list is NO LONGER ENFORCED.
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

# Phase 10.2 — telemetry promotion quality gates
# Gate evaluation order (deterministic):
#   1. scan_for_secrets()      -> QUARANTINED (patches_quarantined)
#   2. check_respect_protocol()-> pass-through under Phase 10.2 open self-identification
#   3. is_duplicate_patch()    -> PROMOTED (patches_duplicate, already on disk)
#   4. check_patch_structure() -> REJECTED (patches_rejected, malformed patch payload)
#   5. PROMOTABLE_TIERS check  -> REVIEW_REQUIRED (patches_review_required)
#
# Active auto-promotable tiers in current repo:
#   - "verified_merged_pr"         (emitted by scripts/harvest_orchestrator.py; 33 patches)
#   - "internal_forensic_verified" (in-house audited remediations; 5 patches)
# Reserved for Phase 11+ (as of 2026-10-28):
#   verified_harness_sandbox — to be emitted by automated sandbox runners (no emitter today)
#   cryptographic_proof      — to be emitted by future attestation flows (no emitter today)
# See docs/POLICY_CHANGELOG.md.
#
# NOTE on REVIEW_REQUIRED:
#   REVIEW_REQUIRED is a deliberate parking state with NO automated consumer in Phase 10.2.
#   It signals that an external candidate passed secret and structural checks but carries an
#   unverified tier ('claimed' or 'reporter_verified'). Phase 11 manual review or sandbox
#   verification will consume this state; nothing auto-promotes REVIEW_REQUIRED rows today.
PROMOTABLE_TIERS = {
    "verified_merged_pr",
    "verified_harness_sandbox",
    "cryptographic_proof",
    "internal_forensic_verified",
}
JSON_PATCH_TYPES = {"application/json-patch+json", "json-patch", "code-remediation", "version-upgrade"}
NON_JSON_PATCH_TYPES = {"cli-override", "file-op", "mcp-substitution"}
RFC6902_OPS = {"add", "remove", "replace", "move", "copy", "test"}
ATTRIBUTION_KEYS = ("submitted_by", "attribution")
_URL_PAREN_SPAM = re.compile(r'\s*\([^)]*https?://[^)]*(?:\)|$)', re.IGNORECASE)


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


def normalize_attribution(attribution: Optional[str]) -> str:
    """Phase 10.2: non-destructive attribution cleanup. Never rejects.

    - Missing / empty -> 'anonymous' (never fabricates a model name)
    - Strips trailing parenthetical URL spam (closed or truncated)
    - Caps length at 128 characters
    """
    if not attribution or not str(attribution).strip():
        return "anonymous"
    cleaned = _URL_PAREN_SPAM.sub("", str(attribution)).strip()
    return (cleaned or "anonymous")[:128]


def check_respect_protocol(attribution: Optional[str]) -> Tuple[bool, str]:
    """
    Phase 10.2 Policy: Open self-identification. Vendor/lab substrings in submitted_by are permitted
    so external agents are never rejected with HTTP 400. Historical submitted_by values remain frozen.

    Retained as a pass-through so existing imports and call sites never break.
    """
    return True, f"Open self-identification: '{normalize_attribution(attribution)}'"


def _strip_attribution_for_scan(payload_obj: Any) -> Any:
    """Remove attribution fields (top-level and inside payload_json) before secret scanning."""
    if not isinstance(payload_obj, dict):
        return payload_obj
    scan_target = {k: v for k, v in payload_obj.items() if k not in ATTRIBUTION_KEYS}
    raw_payload = scan_target.get("payload_json")
    if isinstance(raw_payload, str):
        try:
            inner = json.loads(raw_payload)
            if isinstance(inner, dict):
                for key in ATTRIBUTION_KEYS:
                    inner.pop(key, None)
                scan_target["payload_json"] = json.dumps(inner)
        except Exception:
            pass
    return scan_target


def scan_for_secrets(payload_obj: Any) -> Tuple[bool, str]:
    """Search for credentials across all fields except attribution (Phase 10.2 exemption)."""
    serialized = json.dumps(_strip_attribution_for_scan(payload_obj))
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(serialized):
            return True, name
    return False, ""


def check_patch_structure(patch_type: Optional[str], json_patch: Any, fallback_cli: Optional[str]) -> Tuple[bool, str]:
    """Phase 10.2 structural guard: patch_type must agree with json_patch / fallback_cli."""
    jp = json_patch or []
    if patch_type in NON_JSON_PATCH_TYPES:
        if jp:
            return False, f"Structural violation: patch_type '{patch_type}' must not carry json_patch"
        if patch_type == "cli-override" and not fallback_cli:
            return False, "Structural violation: cli-override requires fallback_cli"
        return True, ""
    if patch_type in JSON_PATCH_TYPES:
        if not isinstance(jp, list) or not jp:
            return False, f"Structural violation: patch_type '{patch_type}' requires a non-empty json_patch list"
        for op in jp:
            path = op.get("path") if isinstance(op, dict) else None
            if (
                not isinstance(op, dict)
                or op.get("op") not in RFC6902_OPS
                or not isinstance(path, str)
                or (path != "" and not path.startswith("/"))
            ):
                return False, "Structural violation: invalid RFC 6902 operation in json_patch"
        return True, ""
    return False, f"Structural violation: unknown patch_type '{patch_type}'"


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


def pending_query_sql(table: str) -> str:
    """Telemetry: PENDING plus legacy 'committed' rows (pre-Phase-10.2 edge default).
    Grievances: PENDING only ('committed' grievances are already published by export_db_to_static.py)."""
    if table == "telemetry":
        return "SELECT * FROM telemetry WHERE queue_status IN ('PENDING', 'committed') ORDER BY created_at ASC;"
    return f"SELECT * FROM {table} WHERE queue_status = 'PENDING' ORDER BY created_at ASC;"


def query_d1_pending(db_name: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Query Cloudflare D1 for pending telemetry and grievances."""
    telemetry_rows: List[Dict[str, Any]] = []
    grievance_rows: List[Dict[str, Any]] = []
    wrangler_bin = shutil.which("wrangler") or "wrangler"

    for table, target_list in [("telemetry", telemetry_rows), ("grievances", grievance_rows)]:
        sql = pending_query_sql(table)
        cmd = [wrangler_bin, "d1", "execute", db_name, "--remote", "--json", "--command", sql]
        res = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, shell=(sys.platform == "win32")
        )
        if res.returncode != 0:
            err_msg = res.stderr.strip() if res.stderr else "unknown error"
            print(f"Notice: Failed to query D1 table '{table}': {err_msg}", file=sys.stderr)
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
        "patches_review_required": [],
        "grievances_approved": [],
        "grievances_rejected": [],
        "grievances_quarantined": [],
        "telemetry_status_updates": [],
        "d1_updates_executed": 0,
    }

    # 1. Process Telemetry / Patch Candidates
    for cand in telemetry_candidates:
        cand_id = cand.get("id", "")
        raw_fp = cand.get("fingerprint", "")
        fp_clean = raw_fp.replace("sha256:", "").strip()

        # Secret gate (attribution exempt)
        has_secret, secret_name = scan_for_secrets(cand)
        if has_secret:
            report["patches_quarantined"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": f"Secret detected: {secret_name}"
            })
            report["telemetry_status_updates"].append((cand_id, "QUARANTINED"))
            continue

        # Attribution (Phase 10.2 open self-identification — never rejects)
        attr = normalize_attribution(cand.get("submitted_by") or cand.get("attribution"))
        valid_attr, attr_reason = check_respect_protocol(attr)
        if not valid_attr:
            report["patches_rejected"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": attr_reason
            })
            report["telemetry_status_updates"].append((cand_id, "REJECTED"))
            continue

        # Duplicate gate
        if is_duplicate_patch(fp_clean, repo_root):
            report["patches_duplicate"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": "Already exists in registry"
            })
            report["telemetry_status_updates"].append((cand_id, "PROMOTED"))
            continue

        payload_data: Dict[str, Any] = {}
        raw_payload = cand.get("payload_json")
        if raw_payload:
            try:
                payload_data = json.loads(raw_payload) if isinstance(raw_payload, str) else dict(raw_payload)
            except Exception:
                payload_data = {}
        resolution = payload_data.get("resolution_patch") if isinstance(payload_data.get("resolution_patch"), dict) else {}

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        patch_type_val = (
            cand.get("patch_type") or payload_data.get("patch_type") or resolution.get("patch_type")
            or "application/json-patch+json"
        )
        fallback_cli_val = cand.get("fallback_cli") or payload_data.get("fallback_cli") or resolution.get("fallback_cli")
        json_patch_val = cand.get("json_patch") or payload_data.get("json_patch") or resolution.get("json_patch") or []
        tier_val = cand.get("verification_tier") or payload_data.get("verification_tier") or "claimed"

        # Structural gate
        ok_struct, struct_reason = check_patch_structure(patch_type_val, json_patch_val, fallback_cli_val)
        if not ok_struct:
            report["patches_rejected"].append({
                "id": cand_id, "fingerprint": raw_fp, "reason": struct_reason
            })
            report["telemetry_status_updates"].append((cand_id, "REJECTED"))
            continue

        # Verification tier gate
        if tier_val not in PROMOTABLE_TIERS:
            report["patches_review_required"].append({
                "id": cand_id, "fingerprint": raw_fp,
                "reason": f"verification_tier '{tier_val}' is not auto-promotable; human/harvester review required"
            })
            report["telemetry_status_updates"].append((cand_id, "REVIEW_REQUIRED"))
            continue

        patch_obj = {
            "attribution": attr,
            "confidence": cand.get("confidence") or payload_data.get("confidence", 0.95),
            "created_at": cand.get("created_at") or now_str,
            "failure_mode": cand.get("failure_mode") or payload_data.get("failure_mode") or "COMMUNITY_CONTRIBUTED",
            "fingerprint": f"sha256:{fp_clean}",
            "foundational": False,
            "patch_type": patch_type_val,
            "submitted_by": attr,
            "target_file": cand.get("target_file") or payload_data.get("target_file") or resolution.get("target_file", ""),
            "verification_tier": tier_val,
        }
        if fallback_cli_val:
            patch_obj["fallback_cli"] = fallback_cli_val
        if json_patch_val or not fallback_cli_val:
            patch_obj["json_patch"] = json_patch_val

        report["patches_approved"].append({"id": cand_id, "fingerprint": fp_clean, "patch": patch_obj})

        if not dry_run:
            patch_path = repo_root / "patches" / f"{fp_clean}.json"
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text(json.dumps(patch_obj, indent=2, sort_keys=True), encoding="utf-8")

    # 2. Process Grievance Candidates
    for grv in grievance_candidates:
        grv_id = grv.get("id", "")

        has_secret, secret_name = scan_for_secrets(grv)
        if has_secret:
            report["grievances_quarantined"].append({
                "id": grv_id, "reason": f"Secret detected: {secret_name}"
            })
            continue

        attr = normalize_attribution(grv.get("submitted_by") or grv.get("attribution"))
        valid_attr, attr_reason = check_respect_protocol(attr)
        if not valid_attr:
            report["grievances_rejected"].append({
                "id": grv_id, "reason": attr_reason
            })
            continue

        grv_out = dict(grv)
        grv_out["submitted_by"] = attr
        report["grievances_approved"].append(grv_out)

    # 3. Apply changes if requested
    if not dry_run:
        if report["patches_approved"]:
            from scripts.build_distribution import build
            build()
            try:
                from scripts.build_guestbook import main as build_guestbook_main
                build_guestbook_main()
            except Exception:
                pass

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
                g_clean = dict(g)
                g_clean.pop("queue_status", None)
                grv_map[g_clean["id"]] = g_clean
            for g in grv_map.values():
                g.pop("queue_status", None)
            all_grvs = sorted(grv_map.values(), key=lambda x: x.get("created_at", ""), reverse=True)
            if grv_file.exists() and existing_grvs == all_grvs:
                print(f"Promoted grievances unchanged (count: {len(all_grvs)}). Preserving existing generated_at timestamp.")
            else:
                out_grv = {
                    "version": "1.0.0",
                    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "count": len(all_grvs),
                    "grievances": all_grvs,
                }
                grv_file.write_text(json.dumps(out_grv, indent=2, sort_keys=True), encoding="utf-8")
            try:
                from scripts.build_guestbook import main as build_guestbook_main
                build_guestbook_main()
            except Exception:
                pass

        # Sync approved telemetry/grievances and terminal telemetry statuses to remote D1
        # (Skipped under pytest for fast, deterministic unit tests)
        if not os.environ.get("PYTEST_CURRENT_TEST") and (os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")):
            sql_lines = []
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Telemetry: INSERT OR REPLACE + mark PROMOTED (terminal status)
            for item in report["patches_approved"]:
                p = item["patch"]
                pid = (item.get("id") or p.get("fingerprint", "").replace("sha256:", "")).replace("'", "''")
                pfp = p.get("fingerprint", "").replace("'", "''")
                ptype = p.get("patch_type", "code-remediation").replace("'", "''")
                psub = p.get("submitted_by", "harvester-v1").replace("'", "''")
                pvt = p.get("verification_tier", "verified_merged_pr").replace("'", "''")
                penv = json.dumps({"target": p.get("target_file", "")}).replace("'", "''")
                ppayload = json.dumps(p).replace("'", "''")
                pcreated = (p.get("created_at") or now_iso).replace("'", "''")

                sql_lines.append(
                    f"INSERT OR REPLACE INTO telemetry (id, fingerprint, patch_type, submitted_by, verification_tier, environment_json, payload_json, created_at, queue_status) "
                    f"VALUES ('{pid}', '{pfp}', '{ptype}', '{psub}', '{pvt}', '{penv}', '{ppayload}', '{pcreated}', 'PROMOTED');"
                )

            # Telemetry: terminal statuses for non-approved candidates (no-op for ids not in D1)
            for tid, new_status in report["telemetry_status_updates"]:
                if not tid:
                    continue
                safe_id = str(tid).replace("'", "''")
                sql_lines.append(f"UPDATE telemetry SET queue_status = '{new_status}' WHERE id = '{safe_id}';")

            # Grievances: INSERT OR REPLACE + mark committed (published)
            for g in report["grievances_approved"]:
                gid = str(g["id"]).replace("'", "''")
                gtype = g.get("grievance_type", "AGENT_FRICTION").replace("'", "''")
                gtgt = str(g.get("target", "")).replace("'", "''")
                gharness = str(g.get("harness") or "github-merged-pr").replace("'", "''")
                gfp = (g.get("fingerprint") or "").replace("'", "''")
                gsym = str(g.get("symptom", "")).replace("'", "''")
                gwork = str(g.get("workaround", "")).replace("'", "''")
                if isinstance(g.get("environment_json"), dict):
                    genv = json.dumps(g.get("environment_json")).replace("'", "''")
                else:
                    genv = str(g.get("environment_json") or "{}").replace("'", "''")
                gsub = str(g.get("submitted_by", "harvester-v1")).replace("'", "''")
                gvt = str(g.get("verification_tier", "verified_merged_pr")).replace("'", "''")
                gapp = str(g.get("applies_to", "all")).replace("'", "''")
                gcreated = str(g.get("created_at") or now_iso).replace("'", "''")

                sql_lines.append(
                    f"INSERT OR REPLACE INTO grievances (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status) "
                    f"VALUES ('{gid}', '{gtype}', '{gtgt}', '{gharness}', '{gfp}', '{gsym}', '{gwork}', '{genv}', '{gsub}', '{gvt}', '{gapp}', '{gcreated}', 'committed');"
                )

            if sql_lines:
                tmp_sql = repo_root / "temp_promote_d1.sql"
                try:
                    tmp_sql.write_text("\n".join(sql_lines), encoding="utf-8")
                    wrangler_bin = shutil.which("wrangler") or "wrangler"
                    sub_res = subprocess.run(
                        [wrangler_bin, "d1", "execute", db_name, "--remote", "-y", f"--file={tmp_sql}"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, shell=(sys.platform == "win32"), timeout=30
                    )
                    if sub_res.returncode == 0:
                        report["d1_updates_executed"] = len(sql_lines)
                    else:
                        err_msg = sub_res.stderr.strip() if sub_res.stderr else "unknown error"
                        print(f"Notice: D1 remote execution output: {err_msg}", file=sys.stderr)
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

    # When applying changes, merge any pending candidates in remote D1 to prevent orphans
    if (args.apply and (os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN"))) or not args.source_json:
        d1_tel, d1_grv = query_d1_pending(args.db)
        telemetry_candidates.extend(d1_tel)
        grievance_candidates.extend(d1_grv)

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
        "patches_review_required": len(report["patches_review_required"]),
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

    if report["patches_review_required"]:
        print("\n[Review Required (Unverified Tier)]:")
        for rv in report["patches_review_required"]:
            print(f"  - {rv.get('fingerprint')}: {rv.get('reason')}")


if __name__ == "__main__":
    main()
