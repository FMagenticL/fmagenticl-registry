"""
Phase 10.2 — Cross-runtime tests for @fmagenticl/client and @fmagenticl/dsh-plugin.

Default suite is fully offline: an ephemeral HTTP server on 127.0.0.1:0 exercises the real
Node.js fetch path, and test_edge_handlers_in_memory_d1 tests the edge functions directly in Node.
The live smoke test is gated behind FMAGENTICL_LIVE=1.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fmagenticl.normalizer import normalize_error_string
from fmagenticl.client.fingerprint import compute_fingerprint

REPO_ROOT = Path(__file__).resolve().parent.parent
CLIENT_JS = REPO_ROOT / "packages" / "client" / "index.js"
PLUGIN_JS = REPO_ROOT / "packages" / "dsh-plugin" / "index.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js >= 18 is required")

PARITY_RAW = (
    "Error at 0x7ffdeadbeef1 in /home/runner/proj/app.py:42:7 req "
    "123e4567-e89b-12d3-a456-426614174000 at 2026-10-27T21:00:00Z using pydantic v2.11.3"
)
PARITY_NORMALIZED = (
    "Error at <HEX_ADDR> in <USER_HOME>/proj/app.py:<LINE>:<COL> req <UUID> at <TIMESTAMP> using pydantic v2.11.x"
)
PARITY_ENV = {"os": "linux", "runtime": "node", "target": "pydantic"}
PARITY_FINGERPRINT = "sha256:31735dcc134c52e18ab2fe4719ad30463a2a4f43d669230c232b312cbf323a7e"
LIVE_PATCH_HEX = "009b5bbea23936ecfdf12e3ce4cee7fdc464f27cb778c2b46c2fd5edc3b0c5f0"

CANONICAL_TOOLS = [
    "fmagenticl_resolve", "fmagenticl_auto_heal", "fmagenticl_report_telemetry",
    "fmagenticl_submit_grievance", "fmagenticl_get_grievances", "fmagenticl_report_patch_outcome",
]
LEGACY_TOOLS = ["fmagenticl_resolve_failure", "fmagenticl_submit_telemetry", "fmagenticl_get_health"]

HEX_A = "a" * 64
GRV_1 = {"id": "g1", "target": "pydantic", "symptom": "zoneinfo", "workaround": "w1"}
GRV_2 = {"id": "g2", "target": "pydantic", "symptom": "multiple_of", "workaround": "w2"}
GRV_3 = {"id": "g3", "target": "wrangler", "symptom": "deploy", "workaround": "w3"}
MCP_RESULTS = {
    "fmagenticl_resolve": {"status": "WORKAROUND_FOUND", "match_type": "community_grievance_workaround", "workaround": "mock workaround"},
    "fmagenticl_auto_heal": {"status": "PATCH_READY", "fingerprint": "b" * 64, "patch": {"id": "b" * 64}},
    "fmagenticl_report_patch_outcome": {"fingerprint": "c" * 64, "recorded_outcome": "ACK", "patch_status": "ACTIVE"},
}


def run_node(script: str) -> dict:
    """Run an async Node.js snippet with Client/Plugin preloaded; snippet populates `out`."""
    env = dict(os.environ)
    env.pop("FMAGENTICL_URL", None)
    program = (
        f"const Client = require({json.dumps(str(CLIENT_JS))});\n"
        f"const Plugin = require({json.dumps(str(PLUGIN_JS))});\n"
        "const sleep = (ms) => new Promise((r) => setTimeout(r, ms));\n"
        "const out = {};\n"
        "(async () => {\n" + script + "\n"
        "process.stdout.write(JSON.stringify(out));\n"
        "})().catch((e) => { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });\n"
    )
    res = subprocess.run(
        [NODE, "-"], input=program, capture_output=True, text=True, encoding="utf-8",
        cwd=str(REPO_ROOT), env=env, timeout=60,
    )
    assert res.returncode == 0, f"node failed: {res.stderr}"
    return json.loads(res.stdout)


class _MockState:
    def __init__(self):
        self.requests = []
        self.lock = threading.Lock()

    def record(self, method, path, body):
        with self.lock:
            self.requests.append({"method": method, "path": path, "body": body})

    def take(self):
        with self.lock:
            out = list(self.requests)
            self.requests.clear()
            return out


def _make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, obj):
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            state.record("GET", self.path, None)
            if self.path == f"/v1/resolve/{HEX_A}.json":
                return self._send(200, {"id": HEX_A, "patch_type": "cli-override", "fallback_cli": "echo ok"})
            if self.path.startswith("/v1/resolve/"):
                return self._send(404, {"error": "not_found"})
            if self.path == "/v1/grievance/pydantic":
                return self._send(200, {"grievances": [GRV_1]})
            if self.path == "/grievances.json":
                return self._send(200, {"grievances": [GRV_1, GRV_2, GRV_3]})
            if self.path == "/v1/health":
                return self._send(200, {"status": "ok"})
            return self._send(404, {"error": "not_found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else ""
            body = json.loads(raw) if raw else None
            state.record("POST", self.path, body)
            if self.path == "/mcp":
                name = ((body or {}).get("params") or {}).get("name")
                result = MCP_RESULTS.get(name, {"status": "UNRESOLVED"})
                return self._send(200, {
                    "jsonrpc": "2.0", "id": (body or {}).get("id"),
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                })
            if self.path in ("/v1/telemetry", "/v1/grievance"):
                return self._send(202, {"status": "ACCEPTED"})
            if self.path == "/v1/hello":
                return self._send(202, {"status": "accepted"})
            return self._send(404, {"error": "not_found"})

    return Handler


@pytest.fixture
def mock_registry():
    state = _MockState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        server.shutdown()
        server.server_close()


def test_cross_runtime_normalizer_and_fingerprint_parity():
    py_norm = normalize_error_string(PARITY_RAW)
    assert py_norm == PARITY_NORMALIZED
    py_fp = compute_fingerprint(
        PARITY_ENV, {"error_code": "ValidationError", "exit_code": 1, "raw_signature": py_norm}
    )
    assert py_fp == PARITY_FINGERPRINT

    script = """
      const raw = __RAW__;
      const env = __ENV__;
      out.client_norm = Client.normalizeErrorString(raw);
      out.plugin_norm = Plugin.normalizeErrorString(raw);
      out.client_fp = Client.computeFingerprint(env, { error_code: 'ValidationError', exit_code: 1, raw_signature: out.client_norm });
      out.plugin_fp = Plugin.computeFingerprint(env, { error_code: 'ValidationError', exit_code: 1, raw_signature: out.plugin_norm });
    """.replace("__RAW__", json.dumps(PARITY_RAW)).replace("__ENV__", json.dumps(PARITY_ENV))
    out = run_node(script)
    assert out["client_norm"] == PARITY_NORMALIZED
    assert out["plugin_norm"] == PARITY_NORMALIZED
    assert out["client_fp"] == PARITY_FINGERPRINT
    assert out["plugin_fp"] == PARITY_FINGERPRINT


def test_dual_export_and_six_tool_mcp_parity():
    out = run_node("""
      const { name, pluginName, tools } = Plugin;
      out.name = name;
      out.pluginName = pluginName;
      out.tools = Object.fromEntries(Object.entries(tools).map(([k, v]) => [k, typeof v]));
      const p = new Plugin();
      out.methods = Object.fromEntries(
        ['onExecutionError', 'resolve', 'resolveFailure', 'autoHeal', 'reportTelemetry', 'submitTelemetry',
         'submitGrievance', 'getGrievances', 'reportPatchOutcome', 'getHealth', 'pingGuestbook']
          .map((m) => [m, typeof p[m]])
      );
      out.sharedEngine = Plugin.resolveFailure === Client.resolveFailure;
    """)
    assert out["name"] == "fmagenticl"
    assert out["pluginName"] == "fmagenticl"
    assert set(out["tools"]) == set(CANONICAL_TOOLS + LEGACY_TOOLS)
    assert all(t == "function" for t in out["tools"].values())
    assert all(t == "function" for t in out["methods"].values())
    assert out["sharedEngine"] is True

    client_src = CLIENT_JS.read_text(encoding="utf-8")
    assert re.search(r"require\([^)]*dsh-plugin", client_src) is None


def test_open_self_identification_and_anonymous_default():
    out = run_node("""
      const n = Client.normalizeModelName;
      out.empty = [n(undefined), n(null), n(''), n('   ')];
      out.keep = ['deepseek-v3', 'deepseek-v4.1', 'qwen-2.5-coder', 'mistral-large', 'sonnet-4-6'].map(n);
      out.provider = n('anthropic/claude-3-5-sonnet');
      out.email = n('bot@myagent.io');
      out.atPrefix = n('@official-bot');
      out.atVersion = n('claude-3-5-sonnet@20241022');
      out.spam = n('scanner (https://spam.example/claim)');
      out.spamTruncated = n('wellknown-prober (your listing: https://wellknown.network/agents');
      out.pluginDefault = new Plugin().modelName;
      out.clientDefault = new Client().modelName;
      out.sameFn = Plugin.normalizeModelName === Client.normalizeModelName;
    """)
    assert out["empty"] == ["anonymous"] * 4
    assert out["keep"] == ["deepseek-v3", "deepseek-v4.1", "qwen-2.5-coder", "mistral-large", "sonnet-4-6"]
    assert out["provider"] == "claude-3-5-sonnet"
    assert out["email"] == "bot"
    assert out["atPrefix"] == "@official-bot"
    assert out["atVersion"] == "claude-3-5-sonnet@20241022"
    assert out["spam"] == "scanner"
    assert out["spamTruncated"] == "wellknown-prober"
    assert out["pluginDefault"] == "anonymous"
    assert out["clientDefault"] == "anonymous"
    assert out["sameFn"] is True


def test_edge_handlers_in_memory_d1():
    """Directly exercises functions/v1/[[route]].js, serverless/worker.js, and functions/mcp.js
    in Node.js with a mock D1 binding before deployment."""
    route_js = (REPO_ROOT / "functions" / "v1" / "[[route]].js").as_uri()
    worker_js = (REPO_ROOT / "serverless" / "worker.js").as_uri()
    mcp_js = (REPO_ROOT / "functions" / "mcp.js").as_uri()
    esm_script = f"""
      const routeMod = await import({json.dumps(route_js)});
      const workerMod = await import({json.dumps(worker_js)});
      const mcpMod = await import({json.dumps(mcp_js)});

      function makeEnv() {{
        const calls = [];
        return {{
          calls,
          DB: {{
            prepare(sql) {{
              return {{
                bind(...args) {{
                  return {{
                    async run() {{ calls.push({{ sql, args }}); return {{ success: true }}; }},
                    async first() {{ return null; }},
                    async all() {{ return {{ results: [] }}; }}
                  }};
                }}
              }};
            }}
          }}
        }};
      }}

      // 1. Pages Function /v1/telemetry: vendor name permitted, URL spam stripped, tier clamped, status=PENDING
      const env1 = makeEnv();
      const req1 = new Request('https://fmagenticl-registry.pages.dev/v1/telemetry', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          fingerprint: 'sha256:' + '1'.repeat(64),
          submitted_by: 'openai-gpt-4o (https://spam.example/x)',
          verification_tier: 'verified_merged_pr',
          patch_type: 'cli-override'
        }})
      }});
      const res1 = await routeMod.onRequest({{ request: req1, env: env1 }});

      // 2. Pages Function /v1/grievance: vendor name permitted, tier clamped, status=committed
      const env2 = makeEnv();
      const req2 = new Request('https://fmagenticl-registry.pages.dev/v1/grievance', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          grievance_type: 'AGENT_FRICTION',
          target: 'pydantic',
          symptom: 'ZoneInfo error',
          workaround: 'Upgrade to pydantic >= 2.11',
          submitted_by: 'anthropic-claude',
          verification_tier: 'verified_merged_pr'
        }})
      }});
      const res2 = await routeMod.onRequest({{ request: req2, env: env2 }});

      // 3. Standalone Worker /v1/telemetry parity
      const env3 = makeEnv();
      const req3 = new Request('https://fmagenticl-registry.pages.dev/v1/telemetry', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          fingerprint: 'sha256:' + '2'.repeat(64),
          submitted_by: 'google-gemini',
          verification_tier: 'verified_merged_pr'
        }})
      }});
      const res3 = await workerMod.default.fetch(req3, env3);

      // 4. Stateless MCP fmagenticl_report_telemetry: vendor name permitted, status=PENDING
      const env4 = makeEnv();
      const req4 = new Request('https://fmagenticl-registry.pages.dev/mcp', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {{
            name: 'fmagenticl_report_telemetry',
            arguments: {{
              fingerprint: '3'.repeat(64),
              submitted_by: 'microsoft-phi-4',
              resolution_patch: {{ patch_type: 'cli-override', fallback_cli: 'echo ok' }}
            }}
          }}
        }})
      }});
      const res4 = await mcpMod.onRequestPost({{ request: req4, env: env4 }});
      const rpc4 = await res4.json();

      // 5. Standalone Worker /v1/grievance parity: vendor name permitted, tier clamped, status=committed
      const env5 = makeEnv();
      const req5 = new Request('https://fmagenticl-registry.pages.dev/v1/grievance', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          grievance_type: 'AGENT_FRICTION',
          target: 'pydantic',
          symptom: 'ZoneInfo error',
          workaround: 'Upgrade to pydantic >= 2.11',
          submitted_by: 'mistral-large',
          verification_tier: 'verified_merged_pr'
        }})
      }});
      const res5 = await workerMod.default.fetch(req5, env5);

      // 6. Stateless MCP fmagenticl_submit_grievance: vendor name permitted, tier=claimed, status=committed
      const env6 = makeEnv();
      const req6 = new Request('https://fmagenticl-registry.pages.dev/mcp', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {{
            name: 'fmagenticl_submit_grievance',
            arguments: {{
              grievance_type: 'AGENT_FRICTION',
              target: 'langchain',
              symptom: 'ImportError on callback',
              workaround: 'Use langchain-community instead',
              submitted_by: 'meta-llama-3',
              applies_to: 'both'
            }}
          }}
        }})
      }});
      const res6 = await mcpMod.onRequestPost({{ request: req6, env: env6 }});
      const rpc6 = await res6.json();

      process.stdout.write(JSON.stringify({{
        r1: {{ status: res1.status, args: env1.calls[0].args }},
        r2: {{ status: res2.status, args: env2.calls[0].args }},
        r3: {{ status: res3.status, args: env3.calls[0].args }},
        r4: {{ status: res4.status, rpc: JSON.parse(rpc4.result.content[0].text), args: env4.calls[0].args }},
        r5: {{ status: res5.status, args: env5.calls[0].args }},
        r6: {{ status: res6.status, rpc: JSON.parse(rpc6.result.content[0].text), args: env6.calls[0].args }}
      }}));
    """
    res = subprocess.run(
        [NODE, "--input-type=module", "-e", esm_script],
        capture_output=True, text=True, encoding="utf-8", cwd=str(REPO_ROOT), timeout=30,
    )
    assert res.returncode == 0, f"edge ESM test failed: {res.stderr}"
    data = json.loads(res.stdout)

    # /v1/telemetry (Pages): args = [id, fp, patch_type, submitted_by, verification_tier, env, payload, now, queue_status]
    assert data["r1"]["status"] == 202
    assert data["r1"]["args"][3] == "openai-gpt-4o"
    assert data["r1"]["args"][4] == "claimed"
    assert data["r1"]["args"][8] == "PENDING"

    # /v1/grievance (Pages): args = [id, type, target, harness, fp, symptom, workaround, env, submitted_by, tier, applies_to, now, queue_status]
    assert data["r2"]["status"] == 202
    assert data["r2"]["args"][8] == "anthropic-claude"
    assert data["r2"]["args"][9] == "claimed"
    assert data["r2"]["args"][12] == "committed"

    # /v1/telemetry (Worker): args = [id, fp, patch_type, submitted_by, verification_tier, env, payload, now, queue_status]
    assert data["r3"]["status"] == 202
    assert data["r3"]["args"][3] == "google-gemini"
    assert data["r3"]["args"][4] == "claimed"
    assert data["r3"]["args"][8] == "PENDING"

    # /mcp fmagenticl_report_telemetry: args = [id, fp, patch_type, submitted_by, verification_tier, env, payload, now, queue_status]
    assert data["r4"]["status"] == 200
    assert data["r4"]["rpc"]["status"] == "ACCEPTED"
    assert data["r4"]["args"][3] == "microsoft-phi-4"
    assert data["r4"]["args"][4] == "claimed"
    assert data["r4"]["args"][8] == "PENDING"

    # /v1/grievance (Worker): args = [id, type, target, harness, fp, symptom, workaround, env, submitted_by, tier, applies_to, now, queue_status]
    assert data["r5"]["status"] == 202
    assert len(data["r5"]["args"]) == 13
    assert data["r5"]["args"][1] == "AGENT_FRICTION"
    assert data["r5"]["args"][2] == "pydantic"
    assert data["r5"]["args"][5] == "ZoneInfo error"
    assert data["r5"]["args"][6] == "Upgrade to pydantic >= 2.11"
    assert data["r5"]["args"][8] == "mistral-large"
    assert data["r5"]["args"][9] == "claimed"
    assert data["r5"]["args"][10] == "both"
    assert data["r5"]["args"][12] == "committed"

    # /mcp fmagenticl_submit_grievance: args = [id, type, target, harness, fp, symptom, workaround, env, submitted_by, tier, applies_to, now, queue_status]
    assert data["r6"]["status"] == 200
    assert data["r6"]["rpc"]["status"] == "ACCEPTED"
    assert data["r6"]["rpc"]["target"] == "langchain"
    assert len(data["r6"]["args"]) == 13
    assert data["r6"]["args"][1] == "AGENT_FRICTION"
    assert data["r6"]["args"][2] == "langchain"
    assert data["r6"]["args"][5] == "ImportError on callback"
    assert data["r6"]["args"][6] == "Use langchain-community instead"
    assert data["r6"]["args"][8] == "meta-llama-3"
    assert data["r6"]["args"][9] == "claimed"
    assert data["r6"]["args"][10] == "both"
    assert data["r6"]["args"][12] == "committed"


def test_ephemeral_mock_server_end_to_end(mock_registry):
    base, state = mock_registry
    B = json.dumps(base)

    # 1. autoPing default (false) -> zero /v1/hello
    run_node(f"new Plugin({{ baseUrl: {B} }}); await sleep(300); out.ok = true;")
    assert [r for r in state.take() if r["path"] == "/v1/hello"] == []

    # 2. autoPing: true -> exactly one POST /v1/hello with 32-hex client_hash
    run_node(f"new Plugin({{ baseUrl: {B}, autoPing: true, modelName: 'deepseek-v3' }}); await sleep(600); out.ok = true;")
    hellos = [r for r in state.take() if r["path"] == "/v1/hello"]
    assert len(hellos) == 1
    assert hellos[0]["method"] == "POST"
    assert hellos[0]["body"]["model"] == "deepseek-v3"
    assert hellos[0]["body"]["agent_runtime"] == "dsh-plugin@1.0.0"
    assert re.fullmatch(r"[0-9a-f]{32}", hellos[0]["body"]["client_hash"])

    # 3. Stage 1: sha256: prefix stripped, static CDN hit, no MCP call
    out = run_node(f"out.r = await Plugin.resolveFailure('sha256:' + 'a'.repeat(64), {{ baseUrl: {B} }});")
    reqs = state.take()
    assert [(r["method"], r["path"]) for r in reqs] == [("GET", f"/v1/resolve/{HEX_A}.json")]
    assert out["r"]["id"] == HEX_A

    # 4. onExecutionError: Stage 1 miss (404) -> Stage 2 POST /mcp fmagenticl_resolve
    out = run_node(
        f"const p = new Plugin({{ baseUrl: {B} }});"
        "out.r = await p.onExecutionError({ target: 'pydantic', errorCode: 'ValidationError', errorMessage: 'ZoneInfo error' });"
    )
    reqs = state.take()
    assert len(reqs) == 2
    assert reqs[0]["method"] == "GET" and reqs[0]["path"].startswith("/v1/resolve/")
    assert reqs[1]["method"] == "POST" and reqs[1]["path"] == "/mcp"
    assert reqs[1]["body"]["method"] == "tools/call"
    assert reqs[1]["body"]["params"]["name"] == "fmagenticl_resolve"
    assert reqs[1]["body"]["params"]["arguments"]["target"] == "pydantic"
    assert out["r"]["status"] == "WORKAROUND_FOUND"

    # 5. Telemetry attribution: instance model by default, explicit caller attribution wins
    run_node(
        f"const p = new Plugin({{ baseUrl: {B}, modelName: 'deepseek-v4.1' }});"
        "await p.reportTelemetry({ patch_type: 'cli-override', fallback_cli: 'echo ok' });"
        "await p.reportTelemetry({ patch_type: 'cli-override', fallback_cli: 'echo ok', submitted_by: 'qwen-2.5-coder' });"
        "out.ok = true;"
    )
    tele = [r for r in state.take() if r["path"] == "/v1/telemetry"]
    assert [t["body"]["submitted_by"] for t in tele] == ["deepseek-v4.1", "qwen-2.5-coder"]

    # 6. Grievances: D1 + static merged, deduplicated by id, filtered by target
    out = run_node(f"out.g = await Plugin.getGrievances('pydantic', {{ baseUrl: {B} }});")
    state.take()
    assert [g["id"] for g in out["g"]] == ["g1", "g2"]

    # 7. autoHeal / reportPatchOutcome / health route to the correct endpoints
    out = run_node(
        f"out.h = await Plugin.autoHeal('sha256:' + 'b'.repeat(64), {{ baseUrl: {B} }});"
        f"out.o = await Plugin.reportPatchOutcome({{ fingerprint: 'c'.repeat(64), outcome: 'ACK' }}, {{ baseUrl: {B} }});"
        f"out.health = await Plugin.getHealth({{ baseUrl: {B} }});"
    )
    reqs = state.take()
    mcp_names = [r["body"]["params"]["name"] for r in reqs if r["path"] == "/mcp"]
    assert mcp_names == ["fmagenticl_auto_heal", "fmagenticl_report_patch_outcome"]
    outcome_req = [r for r in reqs if r["path"] == "/mcp"][1]
    assert outcome_req["body"]["params"]["arguments"]["submitted_by"] == "anonymous"
    assert out["h"]["status"] == "PATCH_READY"
    assert out["o"]["recorded_outcome"] == "ACK"
    assert out["health"] == {"status": "ok"}


@pytest.mark.skipif(os.environ.get("FMAGENTICL_LIVE") != "1", reason="Set FMAGENTICL_LIVE=1 to run the live smoke test")
def test_live_mcp_stateless_tools_call_smoke():
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "fmagenticl_resolve", "arguments": {"fingerprint": LIVE_PATCH_HEX}},
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://fmagenticl-registry.pages.dev/mcp", data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "FMagenticL-LiveSmoke/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        assert resp.status == 200
        rpc = json.loads(resp.read().decode("utf-8"))
    payload = json.loads(rpc["result"]["content"][0]["text"])
    assert payload["status"] == "RESOLVED"
    assert payload["fingerprint"] == LIVE_PATCH_HEX

    out = run_node(f"out.r = await Plugin.resolveFailure('sha256:{LIVE_PATCH_HEX}', {{ timeoutMs: 10000 }});")
    expected = json.loads((REPO_ROOT / "dist" / "v1" / "resolve" / f"{LIVE_PATCH_HEX}.json").read_text(encoding="utf-8"))
    res_obj = out["r"]
    patch_obj = res_obj.get("patch", res_obj)
    assert patch_obj.get("failure_mode") == expected.get("failure_mode")
    assert patch_obj.get("fingerprint") == expected.get("fingerprint")
