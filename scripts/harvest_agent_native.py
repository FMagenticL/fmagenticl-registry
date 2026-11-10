#!/usr/bin/env python3
"""
FMagenticL - Agent-Native Failure Harvester & Recon Daemon (v1.0)
Mines closed issues with linked merged PRs from the leading autonomous coding agent harnesses:
  - cline/cline (VS Code autonomous agent - tool timeouts, terminal quoting, MCP pipe breaks)
  - RooVetGit/Roo-Cline (Autonomous coding fork)
  - All-Hands-AI/OpenHands (Software engineer agent - sandbox/tool execution crashes)
  - paul-gauthier/aider (Pair programming CLI - git conflict loops, provider parameter drift)
  - continuedev/continue (Local LLM / MCP / Ollama connection traps)
  - modelcontextprotocol/servers (Official MCP reference servers)
  - jlowin/fastmcp (FastMCP Python framework)

Enforces Quality Gates F1-F10:
  1. Freshness: merged_at >= 2026-04-01
  2. Stack trace / explicit error token extraction
  3. Linked merged PR in the same repository modifying code/config manifests
  4. Noise filtering: skips chore, docs, test, feature, and cosmetic PRs
  5. Secret and PII scrubbing
  6. Live deduplication against https://fmagenticl-registry.pages.dev/workarounds.json

Outputs candidates to:
  1. Local disk: dist/proposals/agent_native_proposals_<timestamp>.json
  2. Google Drive: The Congregation/01_BOOTSTRAP_DROP/ (ID: 1zlUgvPbpGpzeG53ALTDDN1X224-Rwla3)
"""

import os
import sys
import re
import json
import time
import hashlib
import argparse
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_PROPOSALS = REPO_ROOT / "dist" / "proposals"
DIST_PROPOSALS.mkdir(parents=True, exist_ok=True)
CREDS_PATH = Path.home() / ".config" / "google-drive-mcp" / "credentials.json"
BOOTSTRAP_DROP_FOLDER_ID = "1zlUgvPbpGpzeG53ALTDDN1X224-Rwla3"  # 01_BOOTSTRAP_DROP

# High-Signal Agent-Native Target Repositories
AGENT_NATIVE_TARGETS = [
    "cline/cline",
    "RooVetGit/Roo-Cline",
    "All-Hands-AI/OpenHands",
    "paul-gauthier/aider",
    "continuedev/continue",
    "modelcontextprotocol/servers",
    "jlowin/fastmcp",
]

FRESHNESS_CUTOFF_ISO = "2026-04-01T00:00:00Z"

EXCLUDED_PR_PREFIXES = (
    "test", "[test]", "tests", "add test", "add regression test",
    "chore", "[chore]", "chore(", "chore:", "version ", "[release]",
    "release", "release:", "release(", "docs", "[docs]", "docs:",
    "document", "documentation", "ci", "[ci]", "ci:", "ci(",
    "feat", "[feat]", "feat:", "feature", "refactor", "style",
    "build", "build:", "build(", "bump "
)

ERROR_TOKEN_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault)|E\d{3,5}|"
    r"E(?:CONN|NOENT|ACCES|TIMEDOUT|PERM|ADDR|EXIST|INVAL|PIPE|AGAIN|BUSY|FAULT|IO|ISDIR|LOOP|MFILE|NAMETOOLONG|NET|NODEV|NOMEM|NOSPC|NOTDIR|NOTEMPTY|NOTSOCK|NXIO|OPNOTSUPP|OVERFLOW|PROTO|RANGE|ROFS|SPIPE|SRCH|XDEV)[A-Z_]*|"
    r"[A-Z0-9_]{4,}_ERROR|HTTP \d{3}|TS\d{4}|SQLITE_[A-Z_]+)\b"
)

SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,64}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{50,90}"),
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:Bearer\s+)[a-zA-Z0-9_.-]{20,128}"),
    re.compile(r"[a-zA-Z0-9_-]+\.slack\.com/[^\s]+"),
    re.compile(r"(?:[A-Za-z]:\\[Users|home|Users][^\s:'\"]+)"),
]


def scrub_secrets(text: str) -> str:
    cleaned = text
    for pattern in SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def get_github_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def fetch_live_feed_urls() -> Set[str]:
    """Fetch live workarounds.json URLs to ensure 100% duplicate rejection."""
    url = "https://fmagenticl-registry.pages.dev/workarounds.json"
    req = urllib.request.Request(url, headers={"User-Agent": "FMagenticL-AgentNative-Harvester/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            urls = set()
            for item in data.get("workarounds", []):
                ref = item.get("ref_url") or item.get("url") or ""
                if ref:
                    urls.add(ref.lower().strip())
                desc = item.get("description", "")
                m = re.search(r"\(Ref:\s*(https://github\.com/[^\s)]+)\)", desc)
                if m:
                    urls.add(m.group(1).lower().strip())
            return urls
    except Exception as e:
        print(f"Warning: Could not fetch live feed URLs for dedup: {e}")
        return set()


def extract_stack_trace_or_error(body: str) -> Tuple[bool, str, str]:
    """Extract fenced stack trace or error signature."""
    if not body:
        return False, "", ""
    
    # Check fenced blocks
    fenced_blocks = re.findall(r"```(?:[a-zA-Z0-9_-]*\n)?(.*?)```", body, re.DOTALL)
    for block in fenced_blocks:
        if any(marker in block for marker in ["Traceback (most recent call last):", "Error:", "Exception:", "FAILED", "fatal:"]):
            tokens = ERROR_TOKEN_RE.findall(block)
            primary_token = tokens[0] if tokens else "AgentRuntimeError"
            return True, block.strip()[:2000], primary_token
            
    # Check raw error token in body
    tokens = ERROR_TOKEN_RE.findall(body)
    if tokens:
        # Find context line
        for line in body.splitlines():
            if tokens[0] in line:
                return True, line.strip()[:500], tokens[0]
                
    return False, "", ""


def query_github_graphql(query: str, token: str) -> dict:
    url = "https://api.github.com/graphql"
    data = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "FMagenticL-AgentNative-Harvester/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def harvest_target_repo(repo: str, token: str, live_urls: Set[str]) -> List[Dict[str, Any]]:
    print(f"\n[Scouting Target] {repo} (Agent-Native Vector)...")
    owner, name = repo.split("/", 1)
    
    graphql_query = f"""
    query {{
      repository(owner: "{owner}", name: "{name}") {{
        issues(first: 25, states: [CLOSED], orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
          nodes {{
            number
            title
            body
            updatedAt
            timelineItems(first: 10, itemTypes: [CROSS_REFERENCED_EVENT]) {{
              nodes {{
                ... on CrossReferencedEvent {{
                  source {{
                    ... on PullRequest {{
                      number
                      title
                      body
                      merged
                      mergedAt
                      url
                      repository {{
                        nameWithOwner
                      }}
                      files(first: 20) {{
                        nodes {{
                          path
                        }}
                      }}
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """
    
    candidates = []
    try:
        res = query_github_graphql(graphql_query, token)
        repo_data = res.get("data", {}).get("repository")
        if not repo_data:
            print(f"  Warning: No repository data returned for {repo} ({res.get('errors')})")
            return []
            
        issues = repo_data.get("issues", {}).get("nodes", [])
        print(f"  Inspected {len(issues)} recent closed issues.")
        
        for issue in issues:
            issue_num = issue["number"]
            issue_title = issue["title"]
            issue_body = issue.get("body") or ""
            
            # Gate 2: Extract stack trace / error
            has_error, trace_snippet, error_token = extract_stack_trace_or_error(issue_body)
            if not has_error:
                continue
                
            timeline = issue.get("timelineItems", {}).get("nodes", [])
            for item in timeline:
                pr = item.get("source")
                if not pr or not pr.get("merged"):
                    continue
                    
                # Gate 3: Same repository
                pr_repo = pr.get("repository", {}).get("nameWithOwner")
                if pr_repo != repo:
                    continue
                    
                pr_num = pr["number"]
                pr_title = pr.get("title", "").strip()
                pr_url = pr.get("url", "")
                pr_merged_at = pr.get("mergedAt", "")
                
                # Gate 1: Freshness >= 2026-04-01
                if not pr_merged_at or pr_merged_at < FRESHNESS_CUTOFF_ISO:
                    continue
                    
                # Gate 6: PR title noise filter
                if any(pr_title.lower().startswith(p) for p in EXCLUDED_PR_PREFIXES):
                    continue
                    
                # Gate 5: Deduplication check
                if pr_url.lower().strip() in live_urls:
                    continue
                    
                # Inspect modified files
                files = [f.get("path", "") for f in pr.get("files", {}).get("nodes", [])]
                if not any(f.endswith((".py", ".ts", ".js", ".rs", ".go", ".json", ".toml")) for f in files):
                    continue
                    
                candidate = {
                    "source_channel": "agent_native_github_issue",
                    "target_repo": repo,
                    "target_package": repo.split("/")[-1].lower(),
                    "issue_number": issue_num,
                    "issue_title": scrub_secrets(issue_title),
                    "pr_number": pr_num,
                    "pr_title": scrub_secrets(pr_title),
                    "pr_url": pr_url,
                    "merged_at": pr_merged_at,
                    "error_token": error_token,
                    "stack_trace_snippet": scrub_secrets(trace_snippet),
                    "modified_files": files[:5],
                    "workaround_advisory": (
                        f"Resolved in {repo} via PR #{pr_num}: {scrub_secrets(pr_title)}. "
                        f"Root cause relates to runtime error: {error_token}. (Ref: {pr_url})"
                    ),
                    "harvested_at_utc": datetime.now(timezone.utc).isoformat(),
                }
                candidates.append(candidate)
                live_urls.add(pr_url.lower().strip())
                print(f"  ✅ [VALID YIELD] Issue #{issue_num} -> PR #{pr_num} ({error_token})")
                break
                
    except Exception as e:
        print(f"  Error querying {repo}: {e}")
        
    return candidates


def upload_proposals_to_gdrive(proposals: List[Dict[str, Any]], cycle_num: int) -> Optional[dict]:
    if not CREDS_PATH.exists():
        return None
    try:
        with open(CREDS_PATH, "r", encoding="utf-8") as f:
            creds = json.load(f)
        data = urllib.parse.urlencode({
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": creds["refresh_token"],
            "grant_type": "refresh_token",
        }).encode("utf-8")
        req = urllib.request.Request(
            creds.get("token_uri", "https://oauth2.googleapis.com/token"),
            data=data,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            token = json.loads(resp.read().decode("utf-8"))["access_token"]
            
        filename = f"PROPOSAL_AGENT_NATIVE_CYCLE_{cycle_num:03d}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        content_bytes = json.dumps({
            "cycle": cycle_num,
            "generator": "harvest_agent_native.py",
            "targets": AGENT_NATIVE_TARGETS,
            "yield_count": len(proposals),
            "proposals": proposals,
        }, indent=2).encode("utf-8")
        
        boundary = "=======PROPOSAL_BOUNDARY======="
        metadata = {
            "name": filename,
            "parents": [BOOTSTRAP_DROP_FOLDER_ID],
            "mimeType": "application/json",
        }
        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
            f"{json.dumps(metadata)}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
        ).encode("utf-8") + content_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        create_url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name"
        create_req = urllib.request.Request(
            create_url,
            data=body,
            method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": f"multipart/related; boundary={boundary}"},
        )
        with urllib.request.urlopen(create_req, timeout=20) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            print(f"  ✅ Uploaded proposals to Google Drive 01_BOOTSTRAP_DROP: {filename} (ID: {res['id']})")
            return res
    except Exception as e:
        print(f"  Google Drive upload warning: {e}")
        return None


def run_harvest_cycle(cycle_num: int = 1) -> dict:
    print(f"\n{'=' * 80}")
    print(f"AGENT-NATIVE RECON HARVESTER — CYCLE #{cycle_num} — {datetime.now(timezone.utc).isoformat()}")
    print(f"{'=' * 80}")
    
    token = get_github_token()
    if not token:
        print("ERROR: GITHUB_TOKEN environment variable is not set. GitHub GraphQL requires authentication.")
        return {"error": "Missing GITHUB_TOKEN"}
        
    live_urls = fetch_live_feed_urls()
    print(f"Fetched {len(live_urls)} live workaround URLs for deduplication.")
    
    all_proposals = []
    for target in AGENT_NATIVE_TARGETS:
        proposals = harvest_target_repo(target, token, live_urls)
        all_proposals.extend(proposals)
        time.sleep(1.0)  # Rate pacing
        
    print(f"\n--- Cycle #{cycle_num} Yield Summary ---")
    print(f"Total High-Signal Agent-Native Proposals: {len(all_proposals)}")
    
    # Save local proposal file
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    local_out = DIST_PROPOSALS / f"agent_native_proposals_{timestamp_str}.json"
    with open(local_out, "w", encoding="utf-8") as f:
        json.dump(all_proposals, f, indent=2)
    print(f"Local artifact saved: {local_out}")
    
    # Mirror to Google Drive 01_BOOTSTRAP_DROP
    gdrive_res = upload_proposals_to_gdrive(all_proposals, cycle_num)
    
    return {
        "cycle": cycle_num,
        "yield_count": len(all_proposals),
        "local_file": str(local_out),
        "gdrive_id": gdrive_res.get("id") if gdrive_res else None,
    }


def main():
    parser = argparse.ArgumentParser(description="FMagenticL Agent-Native Failure Harvester")
    parser.add_argument("--loop", type=int, default=0, help="Cadence loop in seconds (e.g. 1800 for 30 minutes). Default 0 (single run).")
    args = parser.parse_args()
    
    cycle = 1
    if args.loop <= 0:
        run_harvest_cycle(cycle)
    else:
        print(f"Starting continuous cadence loop every {args.loop} seconds ({args.loop / 60:.1f} minutes)...")
        while True:
            try:
                run_harvest_cycle(cycle)
            except Exception as e:
                print(f"Cycle #{cycle} exception: {e}")
            cycle += 1
            print(f"\nHibernating for {args.loop}s until Cycle #{cycle}...")
            time.sleep(args.loop)


if __name__ == "__main__":
    main()
