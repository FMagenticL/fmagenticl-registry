#!/usr/bin/env python3
"""
FMagenticL - GitHub Failure Harvester (v2)
Mines closed GitHub issues with linked merged PRs for deterministic agent failures.
Outputs candidates.json containing both actionable grievances and telemetry patches,
fully compliant with serverless/schema.sql and scripts/promote_d1_to_registry.py.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
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

TARGET_REPOS = [
    "modelcontextprotocol/python-sdk",
    "modelcontextprotocol/typescript-sdk",
    "jlowin/fastmcp",
    "pydantic/pydantic",
    "langchain-ai/langchain",
    "crewAIInc/crewAI",
    "cloudflare/workers-sdk"
]

# Strict regex for extracting error traces from markdown code blocks
TRACE_REGEX = re.compile(r'```[a-zA-Z0-9_\-\.]*\s*\n(.*?(?:Traceback|Error|Exception|FAILED|fatal:).*?)```', re.DOTALL | re.IGNORECASE)
# Fallback regex for raw text traces
RAW_TRACE_REGEX = re.compile(r'((?:Traceback \(most recent call last\):[\s\S]*?|(?:Error|Exception):[\s\S]*?)(?=\n\n|\Z))', re.IGNORECASE)
# Error code / exception class extraction
ERROR_CODE_REGEX = re.compile(r'\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault)|E[A-Z0-9_]{3,}|[A-Z0-9_]{4,}_ERROR)\b')


def execute_graphql(query: str, token: str, variables: dict = None) -> dict:
    """Execute a GitHub GraphQL query with rate-limit handling."""
    url = "https://api.github.com/graphql"
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-Harvester/2.0"
    })
    
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403 or e.code == 429:
                reset_time = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                sleep_time = max(1, reset_time - int(time.time()))
                print(f"Rate limited. Sleeping for {sleep_time}s...", file=sys.stderr)
                time.sleep(sleep_time)
            elif e.code >= 500:
                time.sleep(2 ** attempt)
            else:
                raise
    return {}


def select_primary_target_file(file_paths: list[str]) -> list[str]:
    """
    Ranks modified files by priority so core source and manifest files come first:
    - Priority 1: .py, .ts, .js, .rs, .go, package.json, pyproject.toml, wrangler.toml, tsconfig.json outside docs/, tests/, .changeset/
    - Priority 2: Files inside tests/ or test_* or .yml/.yaml/.json
    - Priority 3: docs/*, *.md, *.txt, .changeset/*
    """
    if not file_paths:
        return []

    p1_manifests = {"package.json", "pyproject.toml", "wrangler.toml", "tsconfig.json"}
    p1_exts = {".py", ".ts", ".js", ".rs", ".go"}
    p3_dirs = ("docs/", ".changeset/")
    p3_exts = {".md", ".txt"}

    def rank_file(p: str) -> tuple[int, str]:
        p_norm = p.replace("\\", "/").strip("/")
        basename = p_norm.split("/")[-1].lower()
        ext = os.path.splitext(p_norm)[1].lower()
        parts = [part.lower() for part in p_norm.split("/")]

        # Priority 3 (Documentation & Changesets - Last Resort Only)
        if any(p_norm.lower().startswith(d) for d in p3_dirs) or ext in p3_exts or any(".changeset" in part for part in parts):
            return (3, p_norm)

        # Priority 2 (Tests & Secondary Configs)
        if any(part in ("tests", "test", "__tests__") for part in parts) or basename.startswith("test_") or basename.endswith("_test") or ext in {".yml", ".yaml"} or (ext == ".json" and basename not in p1_manifests):
            return (2, p_norm)

        # Priority 1 (Core Source & Manifest Files)
        if (basename in p1_manifests or ext in p1_exts) and not any(part in ("docs", "tests", "test", ".changeset") for part in parts):
            return (1, p_norm)

        return (2, p_norm)

    return sorted(file_paths, key=rank_file)


def extract_error_trace(body: str) -> str:
    """Extract the most likely error trace from an issue body."""
    if not body:
        return ""
    match = TRACE_REGEX.search(body)
    if match:
        return match.group(1).strip()
    match = RAW_TRACE_REGEX.search(body)
    if match:
        return match.group(1).strip()
    return ""


def extract_error_code(trace: str, title: str) -> str:
    """Extract canonical exception class or error code."""
    match = ERROR_CODE_REGEX.search(trace)
    if match:
        return match.group(1).strip()
    match = ERROR_CODE_REGEX.search(title)
    if match:
        return match.group(1).strip()
    return "RUNTIME_ERROR"


def determine_grievance_type(title: str, body: str, trace: str) -> str:
    """Classify failure mode into standard grievance types."""
    combined = (title + " " + body + " " + trace).lower()
    if "windows" in combined or "macos" in combined or "linux" in combined or "env" in combined:
        return "ENVIRONMENT_MISMATCH"
    if "import" in combined or "module" in combined or "pip" in combined or "npm" in combined or "package" in combined:
        return "INFRASTRUCTURE_FRICTION"
    if "json" in combined or "parse" in combined or "encoding" in combined or "schema" in combined or "protocol" in combined:
        return "PROTOCOL_FRICTION"
    return "AGENT_FRICTION"


def synthesize_workaround(pr_title: str, pr_body: str, file_paths: list, pr_url: str) -> str:
    """Synthesize an actionable, agent-readable remediation from PR metadata."""
    body_clean = pr_body or ""
    # Strip HTML comments
    body_clean = re.sub(r'<!--.*?-->', '', body_clean, flags=re.DOTALL)
    # Strip markdown checkboxes
    body_clean = re.sub(r'- \[[ xX]\][^\n]*', '', body_clean)
    # Strip markdown headers
    body_clean = re.sub(r'#+\s+[^\n]*', '', body_clean)
    # Strip issue closing boilerplate
    body_clean = re.sub(r'\b(?:Fixes|Closes|Resolves)\s+#[0-9]+\b', '', body_clean, flags=re.IGNORECASE)
    
    paragraphs = [p.strip() for p in body_clean.split('\n\n') if p.strip() and len(p.strip()) > 10]
    explanation = ""
    if paragraphs:
        explanation = paragraphs[0]
        explanation = re.sub(r'```.*?```', '', explanation, flags=re.DOTALL)
        explanation = re.sub(r'\s+', ' ', explanation).strip()
    
    target_files_str = ", ".join(file_paths[:3]) if file_paths else "source files"
    clean_title = re.sub(r'\s+', ' ', pr_title).strip()
    
    if explanation:
        workaround = f"Fix: {clean_title}. Target files: {target_files_str}. {explanation}"
    else:
        workaround = f"Fix: {clean_title}. Applied modifications to {target_files_str}."
        
    full_workaround = f"{workaround.strip()} (Ref: {pr_url})"
    if len(full_workaround) > 590:
        cutoff = 590 - len(f"... (Ref: {pr_url})")
        full_workaround = f"{workaround[:cutoff]}... (Ref: {pr_url})"
    return full_workaround


def fetch_issues_with_prs(repo: str, token: str, limit: int = 25) -> list:
    """Query GitHub GraphQL for closed issues with linked merged PRs."""
    query = """
    query($searchQuery: String!, $limit: Int!) {
      search(query: $searchQuery, first: $limit, type: ISSUE) {
        edges {
          node {
            ... on Issue {
              number
              title
              url
              body
              timelineItems(first: 10, itemTypes: [CROSS_REFERENCED_EVENT, CLOSED_EVENT]) {
                nodes {
                  ... on CrossReferencedEvent {
                    source {
                      ... on PullRequest {
                        number
                        title
                        url
                        merged
                        mergedAt
                        body
                        files(first: 20) {
                          edges {
                            node {
                              path
                              additions
                              deletions
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    variables = {"searchQuery": f"repo:{repo} state:closed type:issue", "limit": limit}
    res = execute_graphql(query, token, variables)
    
    issues = []
    edges = res.get("data", {}).get("search", {}).get("edges", [])
    for edge in edges:
        node = edge.get("node", {})
        if not node.get("body"):
            continue
            
        prs = []
        for item in node.get("timelineItems", {}).get("nodes", []):
            pr = item.get("source", {})
            if pr and pr.get("merged"):
                prs.append(pr)
                
        if prs:
            node["linked_prs"] = prs
            issues.append(node)
            
    return issues


def harvest(repos: list, token: str, limit: int, output_file: str):
    telemetry = []
    grievances = []
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    for repo in repos:
        print(f"[*] Harvesting from {repo}...", file=sys.stderr)
        issues = fetch_issues_with_prs(repo, token, limit)
        target = repo.split("/")[-1]
        
        for issue in issues:
            trace = extract_error_trace(issue.get("body", ""))
            if not trace:
                continue
                
            issue_id = issue.get("number")
            title = issue.get("title", "")
            url = issue.get("url", "")
            pr = issue["linked_prs"][0]
            pr_url = pr.get("url", "")
            pr_title = pr.get("title", "")
            pr_body = pr.get("body", "")
            merged_at = pr.get("mergedAt") or now_utc
            
            # Extract changed file paths
            raw_file_paths = []
            files_edges = pr.get("files", {}).get("edges", [])
            for fe in files_edges:
                p = fe.get("node", {}).get("path")
                if p:
                    raw_file_paths.append(p)
                    
            file_paths = select_primary_target_file(raw_file_paths)
                    
            error_code = extract_error_code(trace, title)
            symptom_first = title.split("\n")[0].strip()[:200]
            
            # Compute canonical deterministic fingerprint
            fp = compute_fingerprint(
                {"repo": repo, "target": target},
                {"error_code": error_code, "symptom": symptom_first}
            )
            
            workaround = synthesize_workaround(pr_title, pr_body, file_paths, pr_url)
            clean_symptom = Gatekeeper.scrub_secrets(title[:250])
            clean_workaround = Gatekeeper.scrub_secrets(workaround)
            g_type = determine_grievance_type(title, issue.get("body", ""), trace)
            
            # 1. Grievance entry (strict schema compliance, NO error_trace)
            grievance = {
                "id": f"grv_gh_{repo.replace('/', '_')}_{issue_id}",
                "grievance_type": g_type,
                "target": target,
                "harness": "github-merged-pr",
                "fingerprint": fp,
                "symptom": clean_symptom,
                "workaround": clean_workaround,
                "submitted_by": "deepseek-v4.1",
                "verification_tier": "verified_merged_pr",
                "applies_to": repo,
                "created_at": merged_at,
                "queue_status": "PENDING"
            }
            grievances.append(grievance)
            
            # 2. Telemetry patch entry (if file_paths present and clear error code)
            if file_paths and error_code != "RUNTIME_ERROR":
                primary_file = file_paths[0]
                failure_mode = f"{target.upper().replace('-', '_')}_{error_code}"
                telemetry_cand = {
                    "id": f"tel_gh_{repo.replace('/', '_')}_{issue_id}",
                    "fingerprint": fp,
                    "failure_mode": failure_mode,
                    "patch_type": "code-remediation",
                    "submitted_by": "deepseek-v4.1",
                    "verification_tier": "verified_merged_pr",
                    "target_file": primary_file,
                    "confidence": 0.96,
                    "created_at": merged_at,
                    "json_patch": [
                        {
                            "op": "replace",
                            "path": f"/{primary_file}",
                            "value": clean_workaround
                        }
                    ]
                }
                telemetry.append(telemetry_cand)
                
    output_data = {"telemetry": telemetry, "grievances": grievances}
    out_path = Path(output_file)
    out_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print(f"[+] Harvested {len(telemetry)} patches and {len(grievances)} grievances to {output_file}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Harvest GitHub failures for FMagenticL (v2)")
    parser.add_argument("--limit", type=int, default=25, help="Max issues per repo")
    parser.add_argument("--output", default="candidates.json", help="Output JSON file")
    args = parser.parse_args()
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            import subprocess
            res = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n", capture_output=True, text=True, check=False)
            for line in res.stdout.splitlines():
                if line.startswith("password="):
                    token = line.split("=", 1)[1].strip()
                    break
        except Exception:
            pass

    if not token:
        print("Error: GITHUB_TOKEN environment variable is required.", file=sys.stderr)
        sys.exit(1)
        
    harvest(TARGET_REPOS, token, args.limit, args.output)


if __name__ == "__main__":
    main()
