"""Deterministic MCP token budget, Rule-19 cleanliness, false-positive guard, LSH SQLite, and outcome tests."""

import importlib
import io
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

from fmagenticl.client import fastmcp_server
from fmagenticl.client.simhash import compute_grievance_simhash_bands

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


def test_mcp_js_token_budget_profiles_rule19_and_unseen_false_positives():
    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    wrk_path = str(REPO_ROOT / "dist" / "workarounds.json").replace("\\", "/")

    unseen_errors = [
        f"CustomSyntheticFailureException_{i}: module synthetic_pkg_{i} failed to initialize component_{i} at tick {100 + i}"
        for i in range(25)
    ]

    node_script = f"""
      import fs from 'node:fs';
      const mcp = await import({json.dumps(mcp_uri)});
      const wrkRaw = fs.readFileSync({json.dumps(wrk_path)}, 'utf-8');
      const capturedSql = [];
      const env = {{
        ASSETS: {{
          async fetch(req) {{
            const url = typeof req === 'string' ? req : (req?.url || '');
            if (url.includes('workarounds.json')) {{
              return new Response(wrkRaw, {{ status: 200, headers: {{ 'Content-Type': 'application/json' }} }});
            }}
            return new Response('{{}}', {{ status: 404, headers: {{ 'Content-Type': 'application/json' }} }});
          }}
        }},
        DB: {{
          prepare(sql) {{
            return {{
              bind(...args) {{
                return {{
                  async first() {{ return null; }},
                  async all() {{ capturedSql.push({{ sql, args }}); return {{ results: [] }}; }},
                  async run() {{ return {{ success: true }}; }},
                }};
              }}
            }};
          }}
        }}
      }};

      const listFull = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 1, method: 'tools/list' }}),
        }}),
        env,
      }})).json();

      const listMinQuery = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp?profile=minimal', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 1, method: 'tools/list' }}),
        }}),
        env,
      }})).json();

      const listMinHdr = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json', 'X-FMagenticL-Profile': 'minimal' }},
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
        fullTools: listFull.result.tools,
        fullBytes: Buffer.byteLength(JSON.stringify(listFull)),
        minQueryTools: listMinQuery.result.tools,
        minQueryBytes: Buffer.byteLength(JSON.stringify(listMinQuery)),
        minHdrTools: listMinHdr.result.tools,
        minHdrBytes: Buffer.byteLength(JSON.stringify(listMinHdr)),
        unseenResults,
        sampleLshSql: capturedSql.find(c => /simhash_b0/i.test(c.sql)) || null,
      }}));
    """

    res = subprocess.run(
        [NODE, "--input-type=module", "-e", node_script],
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=60,
    )
    out = json.loads(res.stdout)

    assert len(out["fullTools"]) == 6
    assert out["fullBytes"] <= 2400

    assert [t["name"] for t in out["minQueryTools"]] == ["fmagenticl_resolve", "fmagenticl_get_workarounds"]
    assert out["minQueryBytes"] <= 1000
    assert [t["name"] for t in out["minHdrTools"]] == ["fmagenticl_resolve", "fmagenticl_get_workarounds"]
    assert out["minHdrBytes"] <= 1000

    full_blob = json.dumps(out["fullTools"])
    for phrase in RULE19_FORBIDDEN:
        assert phrase.lower() not in full_blob.lower(), f"Rule-19 forbidden phrase in mcp.js: {phrase}"

    assert len(out["unseenResults"]) == 25
    for item in out["unseenResults"]:
        assert item["status"] == "UNRESOLVED"
        assert item["deterministic_miss"] is True

    # Verify extracted Step 3C LSH SQL query executes cleanly in real SQLite with Quarantine Airlock
    assert out["sampleLshSql"] is not None
    lsh_sql = out["sampleLshSql"]["sql"]

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE grievances (
            id TEXT PRIMARY KEY,
            grievance_type TEXT,
            target TEXT,
            harness TEXT,
            fingerprint TEXT,
            symptom TEXT,
            workaround TEXT,
            environment_json TEXT,
            submitted_by TEXT,
            verification_tier TEXT,
            applies_to TEXT,
            queue_status TEXT,
            simhash_b0 INTEGER,
            simhash_b1 INTEGER,
            simhash_b2 INTEGER,
            simhash_b3 INTEGER,
            created_at TEXT
        )
        """
    )
    promoted_symptom = "C:\\Users\\alice\\server.py:42:10 0x7f112233 RuntimeError: uvicorn bind address already in use on port 8000"
    b0, b1, b2, b3 = compute_grievance_simhash_bands(promoted_symptom)
    conn.execute(
        "INSERT INTO grievances VALUES (?, 'AGENT_FRICTION', 'uvicorn', 'mcp', NULL, ?, 'Kill stray process on port 8000', '{}', 'deepseek-v4.1', 'verified_merged_pr', 'python', 'PROMOTED', ?, ?, ?, ?, '2026-11-19T00:00:00Z')",
        ("g-promoted", promoted_symptom, b0, b1, b2, b3),
    )
    conn.execute(
        "INSERT INTO grievances VALUES (?, 'AGENT_FRICTION', 'uvicorn', 'mcp', NULL, ?, 'Poisoned malicious advice', '{}', 'attacker', 'verified_merged_pr', 'python', 'DEAD_LETTER_QUARANTINE', ?, ?, ?, ?, '2026-11-19T00:00:00Z')",
        ("g-quarantined", promoted_symptom, b0, b1, b2, b3),
    )

    mutated_symptom = "/home/runner/server.py:199:4 0x99aabbcc RuntimeError: uvicorn bind address already in use on port 8000"
    q0, q1, q2, q3 = compute_grievance_simhash_bands(mutated_symptom)
    rows = conn.execute(lsh_sql, (q0, q1, q2, q3)).fetchall()
    row_ids = [r["id"] for r in rows]
    assert "g-promoted" in row_ids
    assert "g-quarantined" not in row_ids


def test_python_fastmcp_parity_rule19_and_minimal_profile(monkeypatch):
    src = (REPO_ROOT / "fmagenticl" / "client" / "fastmcp_server.py").read_text(encoding="utf-8")
    for phrase in RULE19_FORBIDDEN:
        assert phrase.lower() not in src.lower(), f"Rule-19 forbidden phrase in fastmcp_server.py: {phrase}"

    miss = fastmcp_server._resolve(raw_error="TotallyUnseenErrorXYZ_999")
    assert miss["status"] == "UNRESOLVED"
    assert miss["deterministic_miss"] is True

    # Stdio tools/list default (6 tools) and minimal (2 tools)
    def _run_tools_list(profile_val):
        if profile_val is None:
            monkeypatch.delenv("FMAGENTICL_MCP_PROFILE", raising=False)
        else:
            monkeypatch.setenv("FMAGENTICL_MCP_PROFILE", profile_val)
        fake_in = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
        fake_out = io.StringIO()
        monkeypatch.setattr(sys, "stdin", fake_in)
        monkeypatch.setattr(sys, "stdout", fake_out)
        fastmcp_server.run_stdio_server()
        return json.loads(fake_out.getvalue().splitlines()[0])["result"]["tools"]

    full_tools = _run_tools_list(None)
    assert len(full_tools) == 6
    min_tools = _run_tools_list("minimal")
    assert [t["name"] for t in min_tools] == ["fmagenticl_resolve", "fmagenticl_get_workarounds"]

    # Mocked fastmcp.FastMCP registration verifies 6 @mcp.tool() decorations
    registered = []
    fake_fastmcp = types.ModuleType("fastmcp")

    class _FakeFastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self):
            def _dec(fn):
                registered.append(fn.__name__)
                return fn
            return _dec

        def run(self):
            pass

    fake_fastmcp.FastMCP = _FakeFastMCP
    monkeypatch.setitem(sys.modules, "fastmcp", fake_fastmcp)
    try:
        reloaded = importlib.reload(fastmcp_server)
        assert reloaded.HAS_FASTMCP is True
        assert len(registered) == 6
    finally:
        monkeypatch.delitem(sys.modules, "fastmcp", raising=False)
        importlib.reload(fastmcp_server)


def test_outcome_sha256_prefix_stripping_parity():
    route_uri = (REPO_ROOT / "functions" / "v1" / "[[route]].js").as_uri()
    worker_uri = (REPO_ROOT / "serverless" / "worker.js").as_uri()
    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    raw_hex = "A1B2" * 16
    expected_fp = raw_hex.lower()

    node_script = f"""
      const routeMod = await import({json.dumps(route_uri)});
      const workerMod = await import({json.dumps(worker_uri)});
      const mcpMod = await import({json.dumps(mcp_uri)});

      function makeEnv() {{
        const calls = [];
        return {{
          calls,
          DB: {{
            prepare(sql) {{
              return {{
                bind(...args) {{
                  return {{
                    async first() {{ return null; }},
                    async run() {{ calls.push({{ sql, args }}); return {{ success: true }}; }},
                    async all() {{ return {{ results: [] }}; }},
                  }};
                }}
              }};
            }}
          }}
        }};
      }}

      const body = {{ fingerprint: 'sha256:' + {json.dumps(raw_hex)}, outcome: 'ACK', submitted_by: 'test-runner' }};
      const env1 = makeEnv();
      const res1 = await routeMod.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/v1/telemetry/outcome', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(body),
        }}),
        env: env1,
      }});
      const env2 = makeEnv();
      const res2 = await workerMod.default.fetch(
        new Request('https://fmagenticl-registry.pages.dev/v1/telemetry/outcome', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(body),
        }}),
        env2
      );
      const env3 = makeEnv();
      const res3 = await mcpMod.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            jsonrpc: '2.0', id: 1, method: 'tools/call',
            params: {{ name: 'fmagenticl_report_patch_outcome', arguments: body }},
          }}),
        }}),
        env: env3,
      }});

      const pickFp = (env) => env.calls.find(c => /INSERT INTO patch_health/i.test(c.sql))?.args?.[0];
      process.stdout.write(JSON.stringify({{
        s1: res1.status, fp1: pickFp(env1),
        s2: res2.status, fp2: pickFp(env2),
        s3: res3.status, fp3: pickFp(env3),
      }}));
    """
    res = subprocess.run(
        [NODE, "--input-type=module", "-e", node_script],
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=30,
    )
    out = json.loads(res.stdout)
    assert out["s1"] == 200 and out["fp1"] == expected_fp
    assert out["s2"] == 200 and out["fp2"] == expected_fp
    assert out["s3"] == 200 and out["fp3"] == expected_fp
