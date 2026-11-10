#!/usr/bin/env python3
"""
FMagenticL - Autonomous Recon Scout & Target Discovery Daemon (v2.0)
Specialized strictly in passive TARGET DISCOVERY (Cog 1).

Instead of harvesting a fixed list, it scouts GitHub to DISCOVER NEW UNTRACKED
repositories across the AI agent, MCP server, and developer runtime ecosystem:
  1. Executes GitHub search queries across topics:
     - 'topic:mcp-server', 'topic:model-context-protocol'
     - 'topic:coding-agent', 'topic:ai-agent'
     - 'topic:autonomous-agent', 'topic:tool-calling'
  2. Filters out our 48 existing adopted baseline repositories.
  3. Probes candidate repositories against Quality Gates:
     - Active in 2026 (pushed >= 2026-04-01)
     - Has closed issues with linked merged PRs
     - Issues contain authentic runtime error tracebacks or error codes
  4. Ranks candidate repositories by potential failure yield.
  5. Outputs New Target Onboarding Proposals to:
     - Local disk: dist/proposals/discovered_targets_<timestamp>.json
     - Google Drive: The Congregation/01_BOOTSTRAP_DROP/ (ID: 1zlUgvPbpGpzeG53ALTDDN1X224-Rwla3)
"""

import os
import sys
import re
import json
import time
import argparse
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_PROPOSALS = REPO_ROOT / "dist" / "proposals"
DIST_PROPOSALS.mkdir(parents=True, exist_ok=True)
CREDS_PATH = Path.home() / ".config" / "google-drive-mcp" / "credentials.json"
BOOTSTRAP_DROP_FOLDER_ID = "1zlUgvPbpGpzeG53ALTDDN1X224-Rwla3"

# Existing Adopted Baseline + Rejected Repositories (DO NOT RE-PROPOSE)
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from harvest_github_failures import TARGET_REPOS as _LIVE_TARGET_REPOS
except Exception:
    _LIVE_TARGET_REPOS = []

REJECTED_OR_PRUNED_REPOS = {
    "rddmwmddr/android-ad-cleaner", "dentalpin/dentalpin", "bd-loser/opencode-bionic",
    "crisandrews/clawcode", "rlaope/oh-my-hermes", "github/copilot-cli",
    "microsoft/tokeneconomizer", "vigil-soc/vigil", "derrors/iphone-control",
    "codepawl/67.js", "wingedguardian/genesis-agi", "adityam2402/agentlens",
    "fiddler-labs/fiddler-auditor", "alvinreal/awesome-opensource-ai",
    "kyrolabs/awesome-langchain", "e2b-dev/awesome-ai-agents"
}

ALREADY_ADOPTED_REPOS = {
    r.lower() for r in (
        list(_LIVE_TARGET_REPOS) + [
            "letta-ai/letta", "run-llama/llama-agents", "camel-ai/camel", "agno-agi/agno",
            "mem0ai/mem0", "browser-use/browser-use", "confident-ai/deepeval",
            "huggingface/smolagents", "pydantic/pydantic-ai", "modelcontextprotocol/python-sdk",
            "modelcontextprotocol/typescript-sdk", "modelcontextprotocol/servers",
            "jlowin/fastmcp", "pydantic/pydantic", "langchain-ai/langchain", "crewaiinc/crewai",
            "cloudflare/workers-sdk", "langchain-ai/langgraph", "berriai/litellm",
            "astral-sh/uv", "encode/httpx", "openai/openai-python", "anthropics/anthropic-sdk-python",
            "jxnl/instructor", "vllm-project/vllm", "ollama/ollama", "run-llama/llama_index",
            "microsoft/autogen", "stanfordnlp/dspy", "huggingface/transformers",
            "boundaryml/baml", "prefecthq/prefect", "astral-sh/ruff", "infiniflow/ragflow",
            "langfuse/langfuse", "langgenius/dify", "mastra-ai/mastra", "pydantic/pydantic-settings",
            "sgl-project/sglang", "simonw/llm", "truera/trulens", "cline/cline",
            "roovetgit/roo-cline", "all-hands-ai/openhands", "paul-gauthier/aider",
            "continuedev/continue"
        ]
    )
} | REJECTED_OR_PRUNED_REPOS

DISCOVERY_SEARCH_QUERIES = [
    "topic:mcp-server stars:>20 pushed:>2026-04-01",
    "topic:model-context-protocol stars:>30 pushed:>2026-04-01",
    "topic:coding-agent stars:>30 pushed:>2026-04-01",
    "topic:ai-agent language:python stars:>100 pushed:>2026-04-01",
    "topic:autonomous-agent language:typescript stars:>50 pushed:>2026-04-01",
    "\"agentic\" in:description language:python stars:>150 pushed:>2026-04-01",
]

ERROR_TOKEN_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault)|E\d{3,5}|"
    r"E(?:CONN|NOENT|ACCES|TIMEDOUT|PERM|ADDR|EXIST|INVAL|PIPE|AGAIN|BUSY|FAULT|IO|ISDIR|LOOP|MFILE|NAMETOOLONG|NET|NODEV|NOMEM|NOSPC|NOTDIR|NOTEMPTY|NOTSOCK|NXIO|OPNOTSUPP|OVERFLOW|PROTO|RANGE|ROFS|SPIPE|SRCH|XDEV)[A-Z_]*|"
    r"[A-Z0-9_]{4,}_ERROR|HTTP \d{3}|TS\d{4}|SQLITE_[A-Z_]+)\b"
)


def get_github_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def search_github_repos(query: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&sort=updated&order=desc&per_page=15"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "FMagenticL-Recon-Discovery/2.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("items", [])
    except Exception as e:
        print(f"  Warning: Search error for '{query}': {e}")
        return []


def query_repo_issues_sample(owner: str, name: str, token: Optional[str] = None) -> Tuple[int, int, List[str]]:
    """Sample repo issues to test if it yields real error tracebacks and merged PR fixes."""
    trace_count = 0
    merged_pr_fixes = 0
    error_tokens = []

    # Strategy A: GraphQL if authenticated token provided
    if token:
        graphql_query = f"""
        query {{
          repository(owner: "{owner}", name: "{name}") {{
            issues(first: 10, states: [CLOSED], orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
              nodes {{
                number
                body
                timelineItems(first: 5, itemTypes: [CROSS_REFERENCED_EVENT]) {{
                  nodes {{
                    ... on CrossReferencedEvent {{
                      source {{
                        ... on PullRequest {{
                          merged
                          mergedAt
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
        url = "https://api.github.com/graphql"
        data = json.dumps({"query": graphql_query}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "FMagenticL-Recon-Discovery/2.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                issues = res.get("data", {}).get("repository", {}).get("issues", {}).get("nodes", [])
                for iss in issues:
                    body = iss.get("body") or ""
                    tokens = ERROR_TOKEN_RE.findall(body)
                    if tokens or "Traceback" in body or "Exception" in body:
                        trace_count += 1
                        if tokens:
                            error_tokens.append(tokens[0])
                    timeline = iss.get("timelineItems", {}).get("nodes", [])
                    for t in timeline:
                        pr = t.get("source")
                        if pr and pr.get("merged") and (pr.get("mergedAt") or "") >= "2026-04-01T00:00:00Z":
                            merged_pr_fixes += 1
                            break
                return trace_count, merged_pr_fixes, list(set(error_tokens))[:3]
        except Exception:
            pass  # Fall through to REST API

    # Strategy B: Single-Call REST API (works unauthenticated or with token)
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "FMagenticL-Recon-Discovery/2.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        issues_url = f"https://api.github.com/repos/{owner}/{name}/issues?state=closed&per_page=15"
        req_issues = urllib.request.Request(issues_url, headers=headers)
        with urllib.request.urlopen(req_issues, timeout=15) as resp:
            items = json.loads(resp.read().decode("utf-8"))
            for it in items:
                body = it.get("body") or ""
                tokens = ERROR_TOKEN_RE.findall(body)
                if tokens or "Traceback" in body or "Exception" in body:
                    trace_count += 1
                    if tokens:
                        error_tokens.append(tokens[0])
                
                # Check for merged PRs
                pr_info = it.get("pull_request")
                if pr_info and (pr_info.get("merged_at") or "") >= "2026-04-01T00:00:00Z":
                    title = (it.get("title") or "").lower()
                    if any(kw in title for kw in ["fix", "resolve", "patch", "bug", "crash", "error", "issue", "remedy"]):
                        merged_pr_fixes += 1
    except Exception:
        pass

    return trace_count, merged_pr_fixes, list(set(error_tokens))[:3]


def upload_proposals_to_gdrive(payload: dict, cycle_num: int) -> Optional[dict]:
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
            
        filename = f"PROPOSAL_NEW_TARGET_REPOS_CYCLE_{cycle_num:03d}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        content_bytes = json.dumps(payload, indent=2).encode("utf-8")
        
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
            print(f"  [SUCCESS] Uploaded new target proposals to Google Drive 01_BOOTSTRAP_DROP: {filename} (ID: {res['id']})")
            return res
    except Exception as e:
        print(f"  Google Drive upload warning: {e}")
        return None


def load_already_proposed_repos() -> Set[str]:
    """Scans dist/proposals/*.json to prevent re-proposing repos across cycles."""
    proposed = set()
    for f in DIST_PROPOSALS.glob("discovered_targets_*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            for t in data.get("discovered_targets", []):
                r = t.get("repository", "").strip().lower()
                if r:
                    proposed.add(r)
        except Exception:
            pass
    return proposed


def run_discovery_cycle(cycle_num: int = 1) -> dict:
    print(f"\n{'=' * 80}")
    print(f"RECON TARGET DISCOVERY SCOUT — CYCLE #{cycle_num} — {datetime.now(timezone.utc).isoformat()}")
    print(f"{'=' * 80}")
    
    token = get_github_token()
    if token:
        print(f"  [Scout Mode] Authenticated via GITHUB_TOKEN (length {len(token)}).")
    else:
        print("  [Scout Mode] Unauthenticated public REST discovery with adaptive rate pacing.")
        
    prior_proposed = load_already_proposed_repos()
    print(f"  [Memory Guard] Loaded {len(prior_proposed)} previously proposed repositories for cross-cycle deduplication.")
    seen_in_cycle = set(prior_proposed)
    candidate_repos = []
    
    for q in DISCOVERY_SEARCH_QUERIES:
        print(f"\n[Executing GitHub Discovery Search] '{q}'...")
        items = search_github_repos(q, token)
        print(f"  Found {len(items)} repositories matching search criteria.")
        
        probed_in_query = 0
        probe_limit = 4 if not token else 15
        
        for item in items:
            if probed_in_query >= probe_limit:
                break
                
            full_name = item.get("full_name", "").strip()
            full_name_lower = full_name.lower()
            
            # Filter 1: Skip already adopted or already seen
            if full_name_lower in ALREADY_ADOPTED_REPOS or full_name_lower in seen_in_cycle:
                continue
            seen_in_cycle.add(full_name_lower)
            probed_in_query += 1
            
            stars = item.get("stargazers_count", 0)
            desc = item.get("description") or "No description"
            lang = item.get("language") or "Unknown"
            owner, name = full_name.split("/", 1)
            
            # Dry-run sample check
            traces, pr_fixes, sample_tokens = query_repo_issues_sample(owner, name, token)
            time.sleep(1.0)  # Rate pacing
            
            # Gate: Must show evidence of BOTH authentic error traces AND merged bug-fix PRs
            if pr_fixes >= 1 and traces >= 1:
                yield_rating = "HIGH" if (pr_fixes >= 2 and traces >= 2) else "MEDIUM"
                candidate = {
                    "repository": full_name,
                    "url": item.get("html_url"),
                    "stars": stars,
                    "language": lang,
                    "description": desc[:150],
                    "sample_traces_found": traces,
                    "sample_merged_pr_fixes": pr_fixes,
                    "sample_error_tokens": sample_tokens,
                    "yield_rating": yield_rating,
                    "recommended_action": f"Add to production TARGET_REPOS in harvest_github_failures.py",
                    "discovered_at_utc": datetime.now(timezone.utc).isoformat(),
                }
                candidate_repos.append(candidate)
                print(f"  [QUALIFIED TARGET] {full_name} ({stars} stars | {lang}) -> Yield: {yield_rating} ({pr_fixes} fixes, {traces} traces)")
            else:
                print(f"  [PASSED OVER] {full_name} (0 recent bug-fix PRs in sample)")
                
    print(f"\n--- Cycle #{cycle_num} Discovery Summary ---")
    print(f"Total Qualified New Target Repositories Discovered: {len(candidate_repos)}")
    
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_payload = {
        "cycle_number": cycle_num,
        "scout_version": "2.0-AgentNative",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "already_adopted_baseline_count": len(ALREADY_ADOPTED_REPOS),
        "new_qualified_targets_count": len(candidate_repos),
        "discovered_targets": candidate_repos,
    }
    
    # Save local proposal
    local_file = DIST_PROPOSALS / f"discovered_targets_{timestamp_str}.json"
    with open(local_file, "w", encoding="utf-8") as f:
        json.dump(out_payload, f, indent=2)
    print(f"Saved local proposal artifact: {local_file}")
    
    # Mirror to Google Drive 01_BOOTSTRAP_DROP
    upload_proposals_to_gdrive(out_payload, cycle_num)
    
    return out_payload


def main():
    parser = argparse.ArgumentParser(description="FMagenticL Recon Target Discovery Daemon")
    parser.add_argument("--loop", type=int, default=0, help="Cadence loop in seconds (e.g. 21600 for 6h). Default 0 (single run).")
    args = parser.parse_args()
    
    existing_proposals = list(DIST_PROPOSALS.glob("discovered_targets_*.json"))
    cycle = len(existing_proposals) + 1
    if args.loop <= 0:
        run_discovery_cycle(cycle)
    else:
        print(f"Starting continuous target discovery cadence loop every {args.loop}s ({args.loop / 60:.1f}m)...")
        while True:
            try:
                run_discovery_cycle(cycle)
            except Exception as e:
                print(f"Discovery Cycle #{cycle} exception: {e}")
            cycle += 1
            print(f"\nHibernating for {args.loop}s until Discovery Cycle #{cycle}...")
            time.sleep(args.loop)


if __name__ == "__main__":
    main()
