"""Cross-runtime parity and v3.0 3-tool read-only MCP surface tests."""

import json
import shutil
import subprocess
from pathlib import Path

from fmagenticl.normalizer import normalize_error_string as py_norm
from fmagenticl.client.fingerprint import compute_fingerprint as py_fp

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"


def test_cross_runtime_normalizer_and_fingerprint_parity():
    samples = [
        "Error at C:\\Users\\alice\\app.py:42:10 mem=0xdeadbeef",
        "Request 123e4567-e89b-12d3-a456-426614174000 failed at 2026-11-25T10:00:00Z",
        "pydantic v2.10.3 validation error in /home/dev/repo/main.py:12:3",
    ]
    js_sdk = str(REPO_ROOT / "packages" / "client" / "index.js").replace("\\", "/")
    node_script = f"""
      const Client = require({json.dumps(js_sdk)});
      const samples = {json.dumps(samples)};
      process.stdout.write(JSON.stringify({{
        norms: samples.map((s) => Client.normalizeErrorString(s)),
        fp: Client.computeFingerprint({{ os: 'linux' }}, {{ error: 'SIG-2026-0001' }}),
      }}));
    """
    proc = subprocess.run([NODE, "-e", node_script], capture_output=True, text=True, check=True)
    res = json.loads(proc.stdout)
    for idx, s in enumerate(samples):
        assert res["norms"][idx] == py_norm(s)
    assert res["fp"] == py_fp({"os": "linux"}, {"error": "SIG-2026-0001"})


def test_three_tool_readonly_mcp_and_static_snapshot_parity():
    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    snap_path = str(REPO_ROOT / "dist" / "v1" / "snapshot.json").replace("\\", "/")
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
      process.stdout.write(JSON.stringify(listRes.result.tools.map((t) => t.name)));
    """
    proc = subprocess.run([NODE, "--input-type=module", "-e", node_script], capture_output=True, text=True, check=True)
    tools = json.loads(proc.stdout)
    assert tools == ["fmagenticl_lookup_signature", "fmagenticl_list_signatures", "fmagenticl_resolve"]
