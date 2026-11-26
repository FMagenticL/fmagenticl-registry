"""Read-only /mcp and Cloudflare Pages _middleware.js v3.0 contract tests."""

import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"


def test_mcp_js_and_middleware_v3_contract():
    mcp_uri = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    mw_uri = (REPO_ROOT / "functions" / "_middleware.js").as_uri()
    snap_path = str(REPO_ROOT / "dist" / "v1" / "snapshot.json").replace("\\", "/")

    node_script = f"""
      import fs from 'node:fs';
      const mcp = await import({json.dumps(mcp_uri)});
      const mw = await import({json.dumps(mw_uri)});
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

      const lookupId = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {{ name: 'fmagenticl_lookup_signature', arguments: {{ query: 'SIG-2026-0001' }} }} }}),
        }}),
        env,
      }})).json();

      const lookupFlash = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 3, method: 'tools/call', params: {{ name: 'fmagenticl_lookup_signature', arguments: {{ query: 'FLASH-20261113-001' }} }} }}),
        }}),
        env,
      }})).json();

      const lookupCve = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {{ name: 'fmagenticl_lookup_signature', arguments: {{ query: 'CVE-2025-3248' }} }} }}),
        }}),
        env,
      }})).json();

      const listBeh = await (await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 5, method: 'tools/call', params: {{ name: 'fmagenticl_list_signatures', arguments: {{ confidence_tier: 'BEHAVIORAL_INDICATOR' }} }} }}),
        }}),
        env,
      }})).json();

      const headRes = await mcp.onRequestHead({{ request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{ method: 'HEAD' }}) }});
      const hugeRes = await mcp.onRequestPost({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ jsonrpc: '2.0', id: 6, method: 'tools/list', pad: 'x'.repeat(20000) }}),
        }}),
        env,
      }});

      const tel404 = await mw.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/v1/telemetry', {{ method: 'POST' }}),
        next: async () => new Response('ok', {{ status: 200 }}),
      }});

      const cardRes = await mw.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/mcp/server-card'),
        next: async () => new Response('ok', {{ status: 200 }}),
      }});

      process.stdout.write(JSON.stringify({{
        toolNames: listRes.result.tools.map((t) => t.name),
        idMatch: JSON.parse(lookupId.result.content[0].text),
        flashMatch: JSON.parse(lookupFlash.result.content[0].text),
        cveMatch: JSON.parse(lookupCve.result.content[0].text),
        behCount: JSON.parse(listBeh.result.content[0].text).count,
        headStatus: headRes.status,
        hugeStatus: hugeRes.status,
        telStatus: tel404.status,
        card: await cardRes.json(),
        hasHsts: Boolean(cardRes.headers.get('Strict-Transport-Security')),
      }}));
    """
    proc = subprocess.run([NODE, "--input-type=module", "-e", node_script], capture_output=True, text=True, check=True)
    res = json.loads(proc.stdout)
    assert res["toolNames"] == ["fmagenticl_lookup_signature", "fmagenticl_list_signatures", "fmagenticl_resolve"]
    assert res["idMatch"]["status"] == "MATCH_FOUND"
    assert res["idMatch"]["signature"]["id"] == "SIG-2026-0001"
    assert res["flashMatch"]["status"] == "MATCH_FOUND"
    assert res["cveMatch"]["signature"]["id"] == "SIG-2026-0048"
    assert res["behCount"] == 15
    assert res["headStatus"] == 200
    assert res["hugeStatus"] == 413
    assert res["telStatus"] == 404
    assert res["card"]["version"] == "3.0.0"
    assert res["card"]["tools_count"] == 3
    assert res["hasHsts"] is True
