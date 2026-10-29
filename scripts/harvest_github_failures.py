#!/usr/bin/env python3
"""
FMagenticL - GitHub Failure Harvester (v2 - Quality Gated)
Mines closed GitHub issues with linked merged PRs for deterministic agent failures.
Outputs candidates.json containing actionable grievances and clean telemetry patches,
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
from typing import Tuple, Set, List, Dict, Any, Optional

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
    "modelcontextprotocol/servers",
    "jlowin/fastmcp",
    "pydantic/pydantic",
    "langchain-ai/langchain",
    "crewAIInc/crewAI",
    "cloudflare/workers-sdk",
    "langchain-ai/langgraph",
    "BerriAI/litellm",
    "astral-sh/uv",
    "encode/httpx",
    "openai/openai-python",
    "anthropics/anthropic-sdk-python",
    "jxnl/instructor",
    "567-labs/instructor",
    "vllm-project/vllm",
    "ollama/ollama",
    "run-llama/llama_index",
    "microsoft/autogen",
    "stanfordnlp/dspy",
    "huggingface/transformers"
]

REPO_TARGET_MAP = {
    "modelcontextprotocol/servers": "mcp",
    "modelcontextprotocol/python-sdk": "mcp",
    "modelcontextprotocol/typescript-sdk": "mcp",
    "vllm-project/vllm": "vllm",
    "ollama/ollama": "ollama",
    "run-llama/llama_index": "llama-index",
    "microsoft/autogen": "autogen",
    "stanfordnlp/dspy": "dspy",
    "567-labs/instructor": "instructor",
    "jxnl/instructor": "instructor",
    "huggingface/transformers": "transformers",
    "openai/openai-python": "openai",
    "anthropics/anthropic-sdk-python": "anthropic",
    "crewAIInc/crewAI": "crewai",
    "gitlab-org/cli": "gitlab-cli",
    "gitlab/cli": "gitlab-cli",
    "glab": "gitlab-cli"
}

FRESHNESS_CUTOFF = "2026-04-01"
SUBMITTED_BY = "harvester-v1"

# Strict regex for extracting error traces from markdown code blocks
TRACE_REGEX = re.compile(r'```[a-zA-Z0-9_\-\.]*\s*\n(.*?(?:Traceback|Error|Exception|FAILED|fatal:).*?)```', re.DOTALL | re.IGNORECASE)
# Fallback regex for raw text traces
RAW_TRACE_REGEX = re.compile(r'((?:Traceback \(most recent call last\):[\s\S]*?|(?:Error|Exception):[\s\S]*?)(?=\n\n|\Z))', re.IGNORECASE)

# Task 1: Clean error token regex eliminating overly broad E... matching
ERROR_CODE_REGEX = re.compile(
    r'\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault)|E\d{3,5}|E(?:CONN|NOENT|ACCES|TIMEDOUT|PERM|ADDR|EXIST|INVAL|PIPE|AGAIN|BUSY|FAULT|IO|ISDIR|LOOP|MFILE|NAMETOOLONG|NET|NODEV|NOMEM|NOSPC|NOTDIR|NOTEMPTY|NOTSOCK|NXIO|OPNOTSUPP|OVERFLOW|PROTO|RANGE|ROFS|SPIPE|SRCH|XDEV)[A-Z_]*|[A-Z0-9_]{4,}_ERROR)\b'
)


def extract_pr_url(text: str) -> Optional[str]:
    match = re.search(r'(https://github\.com/[^\s\)]+/pull/\d+)', text)
    return match.group(1).lower() if match else None


def load_known_fingerprints_and_urls(repo_root: Path) -> Tuple[Set[str], Set[str]]:
    known_fps: Set[str] = set()
    known_urls: Set[str] = set()

    # 1. Disk patches
    patches_dir = repo_root / "patches"
    if patches_dir.exists():
        for p in patches_dir.glob("*.json"):
            known_fps.add(p.stem)
            known_fps.add(f"sha256:{p.stem}")
            try:
                pdata = json.loads(p.read_text(encoding="utf-8"))
                for op in pdata.get("json_patch", []):
                    u = extract_pr_url(str(op.get("value", "")))
                    if u:
                        known_urls.add(u)
            except Exception:
                pass

    # 2. Registry
    reg_file = repo_root / "dist" / "registry.json"
    if reg_file.exists():
        try:
            reg_data = json.loads(reg_file.read_text(encoding="utf-8"))
            for p in reg_data.get("patches", []):
                pid = p.get("id") or ""
                pfp = p.get("patch_hash") or ""
                if pid:
                    known_fps.add(pid)
                    known_fps.add(f"sha256:{pid}")
                if pfp:
                    known_fps.add(pfp)
        except Exception:
            pass

    # 3. Grievances
    grv_file = repo_root / "dist" / "grievances.json"
    if grv_file.exists():
        try:
            grv_data = json.loads(grv_file.read_text(encoding="utf-8"))
            for g in grv_data.get("grievances", []):
                gid = g.get("id") or ""
                gfp = g.get("fingerprint") or ""
                if gid:
                    known_fps.add(gid)
                if gfp:
                    known_fps.add(gfp)
                u = extract_pr_url(g.get("workaround", ""))
                if u:
                    known_urls.add(u)
        except Exception:
            pass

    # 4. Cross-file deduplication against sandbox/staged_candidates.json
    staged_file = repo_root / "sandbox" / "staged_candidates.json"
    if staged_file.exists():
        try:
            staged_data = json.loads(staged_file.read_text(encoding="utf-8"))
            for item in staged_data.get("telemetry", []) + staged_data.get("grievances", []):
                if item.get("fingerprint"):
                    known_fps.add(item["fingerprint"])
                    known_fps.add(item["fingerprint"].replace("sha256:", ""))
                u = extract_pr_url(str(item))
                if u:
                    known_urls.add(u)
        except Exception:
            pass

    return known_fps, known_urls


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
                print(f"[WARN] GraphQL HTTP error: {e}", file=sys.stderr)
                return {}
        except Exception as e:
            print(f"[WARN] GraphQL unexpected network error: {e}", file=sys.stderr)
            return {}
    return {}


def select_primary_target_file(file_paths: list) -> list:
    if not file_paths:
        return []

    p1_manifests = {"package.json", "pyproject.toml", "wrangler.toml", "tsconfig.json"}
    p1_exts = {".py", ".ts", ".js", ".rs", ".go"}
    p3_dirs = ("docs/", ".changeset/")
    p3_exts = {".md", ".txt"}

    def rank_file(p: str) -> tuple:
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
    match = ERROR_CODE_REGEX.search(trace)
    if match:
        return match.group(1).strip()
    match = ERROR_CODE_REGEX.search(title)
    if match:
        return match.group(1).strip()
    return "RUNTIME_ERROR"


def determine_grievance_type(title: str, body: str, trace: str) -> str:
    combined = (title + " " + body + " " + trace).lower()
    if "windows" in combined or "macos" in combined or "linux" in combined or "env" in combined:
        return "ENVIRONMENT_MISMATCH"
    if "import" in combined or "module" in combined or "pip" in combined or "npm" in combined or "package" in combined:
        return "INFRASTRUCTURE_FRICTION"
    if "json" in combined or "parse" in combined or "encoding" in combined or "schema" in combined or "protocol" in combined:
        return "PROTOCOL_FRICTION"
    return "AGENT_FRICTION"


def synthesize_workaround(pr_title: str, pr_body: str, file_paths: list, pr_url: str) -> str:
    body_clean = pr_body or ""
    # Strip HTML comments
    body_clean = re.sub(r'<!--.*?-->', '', body_clean, flags=re.DOTALL)
    # Strip markdown checkboxes
    body_clean = re.sub(r'- \[[ xX]\][^\n]*', '', body_clean)
    # Strip markdown headers
    body_clean = re.sub(r'#+\s+[^\n]*', '', body_clean)
    # Strip issue closing boilerplate
    body_clean = re.sub(r'\b(?:Fixes|Closes|Resolves)\s+#[0-9]+\b', '', body_clean, flags=re.IGNORECASE)
    # Task 5: Strip Slack thread links and Requested-by footers
    body_clean = re.sub(r'https?://[a-zA-Z0-9_\-\.]+\.slack\.com/[^\s\)"\'>]+', '', body_clean, flags=re.IGNORECASE)
    body_clean = re.sub(r'_?Requested by\s+\*\*[^*]+\*\*[^\n_]*_?', '', body_clean, flags=re.IGNORECASE)
    
    paragraphs = [p.strip() for p in body_clean.split('\n\n') if p.strip() and len(p.strip()) > 10]
    explanation = ""
    if paragraphs:
        explanation = paragraphs[0]
        explanation = re.sub(r'```.*?```', '', explanation, flags=re.DOTALL)
        explanation = re.sub(r'\s+', ' ', explanation).strip()
    
    target_files_str = ", ".join(file_paths[:3]) if file_paths else "source files"
    clean_title = re.sub(r'\s+', ' ', pr_title).strip()
    # Also clean title of requested by or slack links
    clean_title = re.sub(r'https?://[a-zA-Z0-9_\-\.]+\.slack\.com/[^\s\)"\'>]+', '', clean_title, flags=re.IGNORECASE).strip()
    
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
    variables = {"searchQuery": f"repo:{repo} is:issue is:closed linked:pr sort:updated-desc", "limit": limit}
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
                pr_url = pr.get("url", "")
                if not pr_url.lower().startswith(f"https://github.com/{repo.lower()}/pull/"):
                    continue
                
                # Task 5: Filter false-positive PR titles (test-only, release-checklists, docs, chore)
                pr_title = (pr.get("title") or "").strip()
                pr_title_lower = pr_title.lower()
                if any(pr_title_lower.startswith(p) for p in ("test", "add regression test", "chore(release)", "version ", "docs:", "chore:", "release:", "[release]", "ci:")):
                    continue
                    
                prs.append(pr)
                
        if prs:
            node["linked_prs"] = prs
            issues.append(node)
            
    return issues


def harvest(repos: list, token: str, limit: int, output_file: str):
    telemetry = []
    grievances = []
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Task 4: Load known fingerprints and PR URLs across repo and existing files
    known_fps, known_urls = load_known_fingerprints_and_urls(REPO_ROOT)
    
    for repo in repos:
        print(f"[*] Harvesting from {repo}...", file=sys.stderr)
        try:
            issues = fetch_issues_with_prs(repo, token, limit)
        except Exception as e:
            print(f"[WARN] Error harvesting from {repo}: {e}", file=sys.stderr)
            continue
        target = REPO_TARGET_MAP.get(repo) or repo.split("/")[-1].lower().replace("_", "-")
        target_repo = repo
        
        for issue in issues:
            trace = extract_error_trace(issue.get("body", ""))
            if not trace:
                continue
                
            issue_id = issue.get("number")
            title = issue.get("title", "")
            pr = issue["linked_prs"][0]
            pr_url = pr.get("url", "").strip()
            pr_url_lower = pr_url.lower()

            merged_at = pr.get("mergedAt") or now_utc

            # Task 6: Freshness filter (reject issues merged before 2026-04-01)
            if merged_at < FRESHNESS_CUTOFF:
                continue

            # Task 4: Deduplicate by canonical PR URL
            if pr_url_lower in known_urls:
                continue

            pr_title = pr.get("title", "")
            pr_body = pr.get("body", "")

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

            if fp in known_fps or fp.replace("sha256:", "") in known_fps:
                continue

            known_fps.add(fp)
            known_fps.add(fp.replace("sha256:", ""))
            known_urls.add(pr_url_lower)
            
            workaround = synthesize_workaround(pr_title, pr_body, file_paths, pr_url)
            clean_symptom = Gatekeeper.scrub_secrets(title[:250])
            clean_workaround = Gatekeeper.scrub_secrets(workaround)
            g_type = determine_grievance_type(title, issue.get("body", ""), trace)
            
            # 1. Grievance entry (Task 3: submitted_by = 'harvester-v1')
            grievance = {
                "id": f"grv_gh_{repo.replace('/', '_')}_{issue_id}",
                "grievance_type": g_type,
                "target": target,
                "harness": "github-merged-pr",
                "fingerprint": fp,
                "symptom": clean_symptom,
                "workaround": clean_workaround,
                "submitted_by": SUBMITTED_BY,
                "verification_tier": "verified_merged_pr",
                "applies_to": repo,
                "created_at": merged_at,
                "queue_status": "PENDING"
            }
            grievances.append(grievance)
            
            # Task 2: Prose Telemetry Defect
            # For PR code fixes where workaround is English prose (> 200 chars),
            # DO NOT emit a fake RFC 6902 json_patch that would crash client patchers.
            # Only the clean grievance advisory is emitted.
                
    output_data = {"telemetry": telemetry, "grievances": grievances}
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print(f"[+] Harvested {len(telemetry)} patches and {len(grievances)} grievances to {output_file}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Harvest GitHub failures for FMagenticL (v2 - Quality Gated)")
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
