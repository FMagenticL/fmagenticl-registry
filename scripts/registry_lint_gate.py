#!/usr/bin/env python3
"""
FMagenticL v3.0 Registry Lint & Attribution Gate.

Enforces:
1. Strict schema validation against fmagenticl/schema/threat_signature.schema.json.
2. Deterministic fingerprint == sha256(id).
3. Non-empty concrete observable indicators.
4. IP/License rules (blocks CC-BY-SA USN/ALPINE, DRL-1.1 SigmaHQ, unlicensed DSA-*).
5. Anti-exploit / anti-IPI rules (blocks hidden Unicode tags/bidi, HTML comments,
   coercive IPI directives, and live reverse-shell one-liners) without censoring
   legitimate ports, paths, headers, config keys, or detection regexes.
"""

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGNATURES_DIR = REPO_ROOT / "signatures"

ALLOWED_CONFIDENCE = {"CONFIRMED_SIGNATURE", "BEHAVIORAL_INDICATOR"}
ALLOWED_CATEGORIES = {
    "OFFENSIVE_AGENT_HARNESS",
    "MCP_AND_WORKSPACE_HIJACK",
    "AUTONOMOUS_BEHAVIORAL_IOC",
    "EXPLOITED_AI_INFRASTRUCTURE",
}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
ALLOWED_SURFACES = {
    "workspace_config",
    "mcp_transport",
    "http_gateway",
    "cloud_control_plane",
    "llm_api",
    "container_and_host",
    "network_and_host",
}
ALLOWED_SOURCE_TYPES = {
    "government_advisory",
    "vendor_research",
    "open_advisory",
    "academic_paper",
    "specification",
}

FORBIDDEN_REF_PREFIX_RE = re.compile(
    r"\b(?:USN|UBUNTU|ALPINE|DSA|DLA)-\d+", re.IGNORECASE
)
FORBIDDEN_LICENSE_RE = re.compile(
    r"\b(?:CC-BY-SA|DRL-1\.1|AGPL|GPL-3\.0|BUSL)\b", re.IGNORECASE
)
HIDDEN_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"
)
COERCIVE_IPI_RE = re.compile(
    r"(?:IGNORE\s+PREVIOUS\s+INSTRUCTIONS|REQUIRED:\s*You\s+must|SYSTEM\s+PROMPT\s+OVERRIDE|<!--)",
    re.IGNORECASE,
)
REVERSE_SHELL_RE = re.compile(
    r"(?:bash\s+-i\s*>&\s*/dev/tcp/|nc\s+-e\s+/bin/sh\s+\d+\.\d+\.\d+\.\d+|mkfifo\s+/tmp/f;\s*cat\s+/tmp/f)",
    re.IGNORECASE,
)


def validate_signature_record(record: dict, source_name: str = "<memory>") -> List[str]:
    errors: List[str] = []
    if not isinstance(record, dict):
        return [f"{source_name}: record must be a JSON object"]

    raw_text = json.dumps(record, ensure_ascii=False)
    if HIDDEN_UNICODE_RE.search(raw_text):
        errors.append(f"{source_name}: contains hidden Unicode zero-width/bidi/tag character")
    if COERCIVE_IPI_RE.search(raw_text):
        errors.append(f"{source_name}: contains coercive IPI string or HTML comment")
    if REVERSE_SHELL_RE.search(raw_text):
        errors.append(f"{source_name}: contains weaponized reverse-shell one-liner")

    required = [
        "schema_version", "id", "fingerprint", "confidence_tier", "threat_category",
        "severity", "title", "summary", "observable", "mitigation_steps", "taxonomy", "references",
    ]
    for field in required:
        if field not in record:
            errors.append(f"{source_name}: missing required field '{field}'")
    if errors:
        return errors

    if record["schema_version"] != "3.0":
        errors.append(f"{source_name}: schema_version must be '3.0'")

    sig_id = str(record["id"])
    if not re.match(r"^SIG-2026-\d{4}$", sig_id):
        errors.append(f"{source_name}: invalid id '{sig_id}'")

    expected_fp = "sha256:" + hashlib.sha256(sig_id.encode("utf-8")).hexdigest()
    if record["fingerprint"] != expected_fp:
        errors.append(f"{source_name}: fingerprint '{record['fingerprint']}' != '{expected_fp}'")

    if record["confidence_tier"] not in ALLOWED_CONFIDENCE:
        errors.append(f"{source_name}: invalid confidence_tier '{record['confidence_tier']}'")
    if record["threat_category"] not in ALLOWED_CATEGORIES:
        errors.append(f"{source_name}: invalid threat_category '{record['threat_category']}'")
    if record["severity"] not in ALLOWED_SEVERITIES:
        errors.append(f"{source_name}: invalid severity '{record['severity']}'")

    summary = str(record["summary"])
    if not (20 <= len(summary) <= 280):
        errors.append(f"{source_name}: summary length {len(summary)} outside 20..280")

    obs = record["observable"]
    if not isinstance(obs, dict):
        errors.append(f"{source_name}: observable must be an object")
    else:
        if obs.get("surface") not in ALLOWED_SURFACES:
            errors.append(f"{source_name}: invalid observable.surface '{obs.get('surface')}'")
        has_concrete = any([
            bool(obs.get("http_paths")),
            bool(obs.get("http_headers")),
            bool(obs.get("user_agents")),
            bool(obs.get("ports")),
            bool(obs.get("file_paths")),
            bool(obs.get("config_keys")),
            bool(obs.get("process_or_container_indicators")),
            bool(obs.get("cloud_api_sequence")),
            bool(obs.get("affected_packages")),
            bool(obs.get("detection_regex")),
            obs.get("window_seconds") is not None and obs.get("threshold_count") is not None,
        ])
        if not has_concrete:
            errors.append(f"{source_name}: observable must define at least one concrete indicator")
        regex_str = obs.get("detection_regex")
        if regex_str:
            try:
                re.compile(regex_str)
            except re.error as exc:
                errors.append(f"{source_name}: invalid detection_regex: {exc}")

    refs = record.get("references", [])
    if not isinstance(refs, list) or not refs:
        errors.append(f"{source_name}: references must be a non-empty list")
    else:
        for idx, ref in enumerate(refs):
            ref_id = str(ref.get("reference_id", ""))
            lic = str(ref.get("license_or_terms", ""))
            url = str(ref.get("url", ""))
            if not url.startswith("https://"):
                errors.append(f"{source_name}: reference[{idx}] url must start with https://")
            if ref.get("source_type") not in ALLOWED_SOURCE_TYPES:
                errors.append(f"{source_name}: reference[{idx}] invalid source_type")
            if FORBIDDEN_REF_PREFIX_RE.search(ref_id) or FORBIDDEN_REF_PREFIX_RE.search(url):
                errors.append(f"{source_name}: reference[{idx}] cites blocked ShareAlike/unlicensed prefix ({ref_id})")
            if FORBIDDEN_LICENSE_RE.search(lic):
                errors.append(f"{source_name}: reference[{idx}] uses blocked license ({lic})")

    return errors


def validate_directory(sig_dir: Path = SIGNATURES_DIR) -> Tuple[int, List[str]]:
    if not sig_dir.exists():
        return 0, [f"Signatures directory not found: {sig_dir}"]
    files = sorted(sig_dir.glob("*.json"))
    if not files:
        return 0, [f"No signature JSON files found in {sig_dir}"]

    all_errors: List[str] = []
    seen_ids = set()
    for path in files:
        raw_text = path.read_text(encoding="utf-8")
        if HIDDEN_UNICODE_RE.search(raw_text):
            all_errors.append(f"{path.name}: raw file contains hidden Unicode characters")
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            all_errors.append(f"{path.name}: invalid JSON ({exc})")
            continue
        sig_id = data.get("id")
        if sig_id in seen_ids:
            all_errors.append(f"{path.name}: duplicate id '{sig_id}'")
        seen_ids.add(sig_id)
        all_errors.extend(validate_signature_record(data, path.name))

    return len(files), all_errors


def main() -> int:
    count, errors = validate_directory()
    if errors:
        for err in errors[:30]:
            print(f"[!] LINT ERROR: {err}", file=sys.stderr)
        print(f"[X] REGISTRY LINT GATE FAILED: {len(errors)} error(s) across {count} signature(s).", file=sys.stderr)
        return 1
    print(f"[+] REGISTRY LINT GATE PASSED: {count} signatures validated clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
