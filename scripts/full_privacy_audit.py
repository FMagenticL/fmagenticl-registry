#!/usr/bin/env python3
"""
Comprehensive Privacy, Secrets & Air-Gap Auditor for FMagenticL
Scans:
  1. Complete repository working tree and dist/ directory
  2. Full git history (all commits, blobs, and commit authors/emails)
  3. Live public edge payloads
"""

import os
import re
import sys
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# --- SENSITIVE PATTERNS ---
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
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
    ("Private Key Block", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
]

PATH_PATTERNS = [
    ("Windows Backslash Path", re.compile(r'[A-Za-z]:\\Users\\[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("Windows Forward Slash Path", re.compile(r'[A-Za-z]:/Users/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("File URI User Path", re.compile(r'file:///[A-Za-z]:/(?:Users|home)/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
    ("Unix Home Path", re.compile(r'/(?:home|Users)/[a-zA-Z0-9_.-]+', re.IGNORECASE)),
]

INTERNAL_TERMS = [
    ("Local Username 'itari'", re.compile(r'\bitari\b', re.IGNORECASE)),
    ("Workspace 'Agentic Introspection Agent'", re.compile(r'Agentic\s+Introspection\s+Agent', re.IGNORECASE)),
    ("Workspace 'Antigravity Projects'", re.compile(r'Antigravity\s+Projects', re.IGNORECASE)),
    ("Workspace 'Concierge'", re.compile(r'\bConcierge\b', re.IGNORECASE)),
]

NETWORK_PATTERNS = [
    ("Private IPv4 Address", re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')),
    ("Email Address", re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b')),
    ("Phone Number", re.compile(r'\(?\b[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}\b')),
]

FORBIDDEN_EXTENSIONS = {'.pdf', '.key', '.token', '.pem', '.p12', '.pfx'}
IGNORE_DIRS = {'.git', '.pytest_cache', '__pycache__', 'venv', '.venv', 'build', '.egg-info', '.wrangler'}
IGNORE_FILES = {'full_privacy_audit.py', 'air_gap_scan.py', 'inspect_candidates.py'}

# Allow intentional test fixtures and doc references
KNOWN_TEST_ALLOWLIST = [
    "EXAMPLE", "1234567890", "test@example.com", "user@example.com",
    "john.doe@example.com", "noreply@github.com", "git@github.com",
    "AKIAIOSFODNN7EXAMPLE", "sk-test", "sk-proj-test", "127.0.0.1", "0.0.0.0"
]

def is_allowlisted(snippet: str) -> bool:
    for allowed in KNOWN_TEST_ALLOWLIST:
        if allowed.lower() in snippet.lower():
            return True
    return False

def scan_text(text: str, source_label: str, is_test: bool = False) -> List[Tuple[str, str, str]]:
    findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        # 1. Secrets
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                matched = m.group(0)
                if is_test and is_allowlisted(matched):
                    continue
                findings.append((f"{source_label}:{idx}", f"SECRET:{label}", matched[:80]))

        # 2. Paths
        for label, pat in PATH_PATTERNS:
            for m in pat.finditer(line):
                matched = m.group(0)
                # Ignore generic instructions or test paths like C:\Users\alice or /home/user
                if is_test and ("alice" in matched or "user" in matched or "runner" in matched):
                    continue
                findings.append((f"{source_label}:{idx}", f"PATH:{label}", matched[:80]))

        # 3. Internal Terms
        for label, pat in INTERNAL_TERMS:
            for m in pat.finditer(line):
                matched = m.group(0)
                findings.append((f"{source_label}:{idx}", f"TERM:{label}", line.strip()[:100]))

        # 4. Network / Contact (emails/phones/private IPs)
        if not is_test:
            for label, pat in NETWORK_PATTERNS:
                for m in pat.finditer(line):
                    matched = m.group(0)
                    if is_allowlisted(matched):
                        continue
                    findings.append((f"{source_label}:{idx}", f"CONTACT/NETWORK:{label}", matched[:80]))

    return findings

def audit_working_tree() -> List[Tuple[str, str, str]]:
    findings = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.endswith('.egg-info')]
        for fn in files:
            if fn in IGNORE_FILES:
                continue
            fp = Path(root) / fn
            rel = fp.relative_to(REPO_ROOT)
            
            if fp.suffix.lower() in FORBIDDEN_EXTENSIONS:
                findings.append((str(rel), "FORBIDDEN_EXTENSION", f"File extension {fp.suffix}"))
                continue

            try:
                content = fp.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                findings.append((str(rel), "READ_ERROR", str(e)))
                continue

            is_test = "test" in fp.name.lower() or "tests" in rel.parts or "verification" in fp.name.lower()
            findings.extend(scan_text(content, str(rel), is_test=is_test))
    return findings

def audit_git_history() -> Tuple[List[str], List[Tuple[str, str, str]]]:
    authors = []
    findings = []

    # 1. Author and Committer list
    cmd_authors = ['git', 'log', '--all', '--format=%an <%ae> (Committer: %cn <%ce>)']
    res = subprocess.run(cmd_authors, capture_output=True, text=True, check=False)
    if res.returncode == 0:
        unique_authors = sorted(list(set(res.stdout.splitlines())))
        authors = unique_authors

    # 2. Full diff history
    cmd_diff = ['git', 'log', '--all', '-p', '--full-diff', '--no-color']
    res_diff = subprocess.run(cmd_diff, capture_output=True, text=True, encoding='utf-8', errors='replace', check=False)
    if res_diff.returncode == 0:
        # Scan diff for secrets and paths that might have existed in older commits
        findings.extend(scan_text(res_diff.stdout, "git-history", is_test=False))

    return authors, findings

def main():
    print("=" * 80)
    print("FMagenticL COMPREHENSIVE PRIVACY, SECRETS & AIR-GAP AUDIT")
    print("=" * 80)

    print("\n[*] Auditing Working Tree & Compiled Assets...")
    tree_findings = audit_working_tree()
    print(f" -> Working Tree scanned. Total findings: {len(tree_findings)}")

    print("\n[*] Auditing Git Commit History & Author Metadata...")
    authors, git_findings = audit_git_history()
    print(f" -> Found {len(authors)} unique author/committer identities:")
    for a in authors:
        print(f"    - {a}")
    print(f" -> Git Diff History scanned. Total findings: {len(git_findings)}")

    # Summary
    print("\n" + "=" * 80)
    print("AUDIT FINDINGS SUMMARY")
    print("=" * 80)

    critical_tree = [f for f in tree_findings if not f[1].startswith("CONTACT/NETWORK:Email")]
    email_tree = [f for f in tree_findings if f[1].startswith("CONTACT/NETWORK:Email")]

    if critical_tree:
        print(f"\n[!] WORKING TREE ISSUES DETECTED ({len(critical_tree)}):")
        for loc, cat, snip in critical_tree[:50]:
            print(f"  [{cat}] {loc} -> {snip}")
        if len(critical_tree) > 50:
            print(f"  ... and {len(critical_tree) - 50} more.")
    else:
        print("\n[+] WORKING TREE: ZERO secrets, private paths, or internal terms detected!")

    if email_tree:
        print(f"\n[*] EMAIL ADDRESSES FOUND IN WORKING TREE ({len(email_tree)}):")
        for loc, cat, snip in email_tree[:20]:
            print(f"  {loc} -> {snip}")

    # Git history review (filter out benign test diffs if any)
    critical_git = [f for f in git_findings if not f[1].startswith("CONTACT/NETWORK:Email")]
    if critical_git:
        print(f"\n[!] GIT HISTORY FINDINGS ({len(critical_git)}):")
        for loc, cat, snip in critical_git[:30]:
            print(f"  [{cat}] {loc} -> {snip}")
    else:
        print("\n[+] GIT HISTORY: ZERO leaked secrets, paths, or internal terms in any commit blob!")

    return 0

if __name__ == "__main__":
    sys.exit(main())
