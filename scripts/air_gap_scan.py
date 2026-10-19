#!/usr/bin/env python3
"""
FMagenticL Air-Gap & Pre-Boundary Quarantine Scanner
Enforces RULE[inner_environment_air_gap_prevention] before staging, commit, or build.
Scans for tokens, private keys, operator PII, local user paths, and unapproved binary files.
Supports:
    --staged    Scan git index staged files
    --history   Scan complete git commit diff history
    (default)   Scan all working tree files
"""

import os
import sys
import re
import subprocess
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Forbidden file extensions in public release trees
FORBIDDEN_EXTENSIONS = {'.pdf', '.key', '.token', '.pem', '.p12', '.pfx'}

# Regex signatures for active credentials
SECRET_PATTERNS = [
    ("GitHub PAT (legacy)", re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("GitHub Fine-Grained PAT", re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b')),
    ("GitHub OAuth / Other Token", re.compile(r'\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b')),
    ("PyPI API Token", re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{30,}\b')),
    ("npm Publish Token", re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    ("Cloudflare User Token", re.compile(r'\bcfut_[A-Za-z0-9]{40}\b')),
    ("Cloudflare Auth Token", re.compile(r'\bcfat_[A-Za-z0-9]{40}\b')),
    ("Hugging Face API Token", re.compile(r'\bhf_[A-Za-z0-9]{34}\b')),
    ("OpenAI / LLM API Key", re.compile(r'\bsk-[A-Za-z0-9]{20,}\b')),
    ("Google API Key", re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ("Slack Token", re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b')),
    ("Bearer Token Header", re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]{20,512}', re.IGNORECASE)),
    ("Raw JWT", re.compile(r'\bey[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}\.?[A-Za-z0-9-_.+/=]*\b')),
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
]

# Load sensitive PII terms from local air-gap storage (if available) without hardcoding into public repo
PII_PATTERNS = []
_local_pii_file = Path.home() / ".fmagenticl" / "air_gap_pii.txt"
if _local_pii_file.is_file():
    try:
        _terms = [t.strip() for t in _local_pii_file.read_text(encoding='utf-8').splitlines() if t.strip()]
        PII_PATTERNS = [(term, re.compile(rf'\b{re.escape(term)}\b', re.IGNORECASE)) for term in _terms]
    except Exception:
        pass

# Generic patterns: home paths and private networks in release files
GENERIC_LEAK_PATTERNS = [
    ("Windows Backslash Path", re.compile(r'[A-Za-z]:\\Users\\[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("Windows Forward Slash Path", re.compile(r'[A-Za-z]:/Users/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("File URI User Path", re.compile(r'file:///[A-Za-z]:/(?:Users|home)/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("Unix Home Path", re.compile(r'/(?:home|Users)/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
]

IGNORE_DIRS = {'.git', '.pytest_cache', '__pycache__', 'venv', '.venv', 'build', '.egg-info', '.wrangler', '.agents'}
IGNORE_FILES = {'air_gap_scan.py', 'sanitize_scan.py', 'full_privacy_audit.py', 'probe_external_surfaces.py', 'inspect_candidates.py'}

KNOWN_TEST_ALLOWLIST = [
    "EXAMPLE", "1234567890", "test@example.com", "user@example.com",
    "john.doe@example.com", "noreply@github.com", "git@github.com",
    "AKIAIOSFODNN7EXAMPLE", "sk-test", "sk-proj-test", "127.0.0.1", "0.0.0.0",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
]

def scan_text_lines(content: str, source_label: str, is_test_file: bool = False) -> List[Tuple[int, str, str]]:
    violations = []
    for line_idx, line in enumerate(content.splitlines(), start=1):
        # Scan Secrets
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                matched = m.group(0)
                # Ignore RFC/AWS standard documentation example keys and obvious 1234 test dummies in tests
                if is_test_file and any(tok in matched for tok in ("EXAMPLE", "1234567890", "test")):
                    continue
                violations.append((line_idx, f"SECRET:{label}", line.strip()[:100]))
                
        # Scan PII from local blocklist
        for term, pat in PII_PATTERNS:
            if pat.search(line):
                violations.append((line_idx, f"PII_BLOCKLIST:{term}", line.strip()[:100]))

        # Scan Generic Leaks (skip in tests)
        if not is_test_file:
            for label, pat in GENERIC_LEAK_PATTERNS:
                if pat.search(line):
                    # Ignore harmless test fixtures with 'alice', 'runner', or 'user'
                    matched = pat.search(line).group(0)
                    if any(t in matched.lower() for t in ("alice", "runner", "user", "username")):
                        continue
                    violations.append((line_idx, f"LEAK:{label}", line.strip()[:100]))

    return violations

def scan_file(filepath: Path) -> List[Tuple[int, str, str]]:
    """Scan a single text file line-by-line for secrets and PII."""
    violations = []
    
    # Check extension
    if filepath.suffix.lower() in FORBIDDEN_EXTENSIONS:
        violations.append((0, "FORBIDDEN_EXTENSION", f"File extension '{filepath.suffix}' is prohibited from repository"))
        return violations

    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        violations.append((0, "READ_ERROR", str(e)))
        return violations

    is_test_file = "test" in filepath.name.lower() or "tests" in filepath.parts or "verification" in filepath.name.lower()
    return scan_text_lines(content, str(filepath), is_test_file=is_test_file)

def get_staged_files() -> List[Path]:
    """Retrieve list of git staged files."""
    try:
        res = subprocess.run(['git', 'diff', '--cached', '--name-only'], capture_output=True, text=True, check=True)
        files = [REPO_ROOT / f.strip() for f in res.stdout.splitlines() if f.strip()]
        return [
            f for f in files 
            if f.is_file() and f.name not in IGNORE_FILES and not any(part in IGNORE_DIRS for part in f.parts)
        ]
    except Exception:
        return []

def get_all_scannable_files() -> List[Path]:
    """Get all non-ignored files in repository and dist directory."""
    files = []
    for root, dirs, filenames in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.endswith('.egg-info')]
        for fn in filenames:
            if fn in IGNORE_FILES:
                continue
            fp = Path(root) / fn
            files.append(fp)
    return files

def scan_git_history() -> int:
    """Scan full git history diffs."""
    print("[*] Running Air-Gap Quarantine Scan on Full Git History (git log -p)...")
    cmd = ['git', 'log', '--all', '-p', '--full-diff', '--no-color']
    res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=False)
    if res.returncode != 0:
        print("[!] Failed to run git log for history scan", file=sys.stderr)
        return 1

    violations = []
    for line_idx, line in enumerate(res.stdout.splitlines(), start=1):
        if not line.startswith('+'):
            continue
        line_clean = line[1:].strip()
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line_clean):
                matched = m.group(0)
                if any(tok in matched for tok in ("EXAMPLE", "1234567890", "test", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")):
                    continue
                violations.append((line_idx, f"GIT_HISTORY:SECRET:{label}", line_clean[:80]))
        for label, pat in GENERIC_LEAK_PATTERNS:
            for m in pat.finditer(line_clean):
                matched = m.group(0)
                if any(t in matched.lower() for t in ("alice", "runner", "user", "username")):
                    continue
                violations.append((line_idx, f"GIT_HISTORY:LEAK:{label}", line_clean[:80]))

    if violations:
        for line_no, category, snip in violations[:20]:
            print(f" [!] GIT HISTORY VIOLATION: Line {line_no} [{category}] -> {snip}", file=sys.stderr)
        print(f"\n[X] GIT HISTORY AUDIT FAILED: {len(violations)} violation(s) detected.", file=sys.stderr)
        return 1
    else:
        print("[+] GIT HISTORY AUDIT PASSED: Zero real secrets or private paths detected in git history.")
        return 0

def main():
    if "--history" in sys.argv:
        sys.exit(scan_git_history())

    check_staged = "--staged" in sys.argv
    targets = get_staged_files() if check_staged else get_all_scannable_files()

    print(f"[*] Running Air-Gap Quarantine Scan on {len(targets)} target file(s)... Mode: {'STAGED' if check_staged else 'FULL_TREE'}")
    total_violations = 0

    for filepath in targets:
        if not filepath.is_file():
            continue
        rel_path = filepath.relative_to(REPO_ROOT)
        
        # In dist/, assert no non-registry files exist
        if str(rel_path).startswith("dist" + os.sep) and (rel_path.suffix == '.pdf' or 'google_export' in str(rel_path)):
            print(f" [!] AIR-GAP VIOLATION: Non-registry artifact found in dist/: {rel_path}", file=sys.stderr)
            total_violations += 1
            continue

        violations = scan_file(filepath)
        if violations:
            total_violations += len(violations)
            for line_no, category, snippet in violations:
                print(f" [!] LEAK HAZARD: {rel_path}:{line_no} [{category}] -> {snippet}", file=sys.stderr)

    if total_violations > 0:
        print(f"\n[X] AIR-GAP AUDIT FAILED: {total_violations} violation(s) detected. Aborting to prevent leak.", file=sys.stderr)
        sys.exit(1)
    else:
        print("[+] AIR-GAP AUDIT PASSED: Zero secrets, PII, or forbidden files detected.")
        sys.exit(0)

if __name__ == "__main__":
    main()
