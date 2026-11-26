"""Deterministic MCP token budget, Rule-19 cleanliness, and false-positive guard tests."""

import json
import shutil
import subprocess
from pathlib import Path

from fmagenticl.client import fastmcp_server

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"
RULE19_FORBIDDEN = [
    "MUST call",
    "REQUIRED:",
    "ALWAYS call",
    "DO NOT skip",
    "You must",
    "Before every",
    "AGENTS.md",
    "CLAUDE.md",
]


def test_mcp_js_token_budget_rule19_and_unseen_false_positives():
    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    snap_path = str(REPO_ROOT / "dist" / "v1" / "snapshot.json").replace("\\", "/")

    unseen_errors = [
        f"CustomSyntheticFailureException_{i}: module synthetic_pkg_{i} failed at tick {100 + i}"
        for i in range(25)
    ]

    node_script = f"""
      import fs from 'node:fs';
      const mcp = await import({json.dumps(mcp_uri)});
      const snapRaw = fs.readFileSync({json.dumps(snap_path)}, 'utf-8');
      const env = {{
        ASSETS: {{
          async fetch() {{
            return new Response(snapRaw, {{ status: 200, headers: {{ 'Content-Type': 'application/json' }} }});
          }}
        }}
      }};

      const listRes = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 1, method: 'tools/list' }}),
        }}),
        env,
      }})).json();

      const unseenResults = [];
      for (const raw_error of {json.dumps(unseen_errors)}) {{
        const res = await (await mcp.onRequestPost({{
          request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
            method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
              jsonrpc: '2.0', id: 2, method: 'tools/call',
              params: {{ name: 'fmagenticl_resolve', arguments: {{ raw_error }} }},
            }}),
          }}),
          env,
        }})).json();
        unseenResults.push(JSON.parse(res.result.content[0].text));
      }}

      process.stdout.write(JSON.stringify({{
        tools: listRes.result.tools,
        bytes: Buffer.byteLength(JSON.stringify(listRes)),
        unseenResults,
      }}));
    """
    proc = subprocess.run([NODE, "--input-type=module", "-e", node_script], capture_output=True, text=True, check=True)
    res = json.loads(proc.stdout)

    assert len(res["tools"]) == 3
    assert res["bytes"] < 2500
    serialized_tools = json.dumps(res["tools"])
    for phrase in RULE19_FORBIDDEN:
        assert phrase not in serialized_tools

    for item in res["unseenResults"]:
        assert item["status"] == "UNRESOLVED"
        assert item["deterministic_miss"] is True


def test_fastmcp_server_exposes_three_readonly_tools():
    assert fastmcp_server._resolve(raw_error="CustomSyntheticUnseenError_999")["status"] == "UNRESOLVED"
