/**
 * FMagenticL v3.0.0 Remote MCP Server — Stateless Read-Only Streamable HTTP
 * Route: https://fmagenticl-registry.pages.dev/mcp
 * Spec: MCP 2025-03-26 (JSON-RPC 2.0 over HTTP POST, stateless, zero D1 dependency)
 */

const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "fmagenticl-registry-mcp", version: "3.0.0" };
const MAX_BODY_BYTES = 16384;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id, X-FMagenticL-Profile",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};

const JSON_HEADERS = {
  ...CORS_HEADERS,
  "Content-Type": "application/json; charset=utf-8",
};

const TOKEN_EXTRACT_RE = /(SIG-2026-\d{4}|CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|FLASH-\d{8}-\d{3}|FIN-\d{4}-R\d{3}|(?:sha256:)?[0-9a-fA-F]{64})/i;

const TOOLS = [
  {
    name: "fmagenticl_lookup_signature",
    description: "Exact lookup of a signed malicious AI agent signature by SIG-2026-XXXX, CVE, GHSA, advisory ID, or sha256 fingerprint.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Signature ID, CVE, GHSA, advisory ID, or sha256 hex." },
      },
      required: ["query"],
    },
  },
  {
    name: "fmagenticl_list_signatures",
    description: "List signed threat signatures filtered by confidence_tier, threat_category, surface, or severity.",
    inputSchema: {
      type: "object",
      properties: {
        confidence_tier: { type: "string", enum: ["CONFIRMED_SIGNATURE", "BEHAVIORAL_INDICATOR"] },
        threat_category: {
          type: "string",
          enum: ["OFFENSIVE_AGENT_HARNESS", "MCP_AND_WORKSPACE_HIJACK", "AUTONOMOUS_BEHAVIORAL_IOC", "EXPLOITED_AI_INFRASTRUCTURE"],
        },
        surface: { type: "string" },
        severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM"] },
        limit: { type: "integer", minimum: 1, maximum: 200 },
      },
    },
  },
  {
    name: "fmagenticl_resolve",
    description: "Read-only exact resolver by signature ID, CVE/GHSA/advisory token, or sha256 fingerprint.",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string" },
        target: { type: "string" },
        raw_error: { type: "string" },
      },
    },
  },
];

function jsonRpcError(id, code, message, status = 200) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }), {
    status,
    headers: JSON_HEADERS,
  });
}

function jsonRpcResult(id, result) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result }), {
    status: 200,
    headers: JSON_HEADERS,
  });
}

async function readBoundedBody(request) {
  if (!request.body) return { ok: true, text: "" };
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      try { await reader.cancel(); } catch {}
      return { ok: false, tooLarge: true };
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
}

async function loadSnapshot(env) {
  if (!env || !env.ASSETS || typeof env.ASSETS.fetch !== "function") return null;
  try {
    const res = await env.ASSETS.fetch(new Request("https://fmagenticl-registry.pages.dev/v1/snapshot.json"));
    if (res.status !== 200) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function lookupInSnapshot(snapshot, query) {
  if (!snapshot || !query) return null;
  const q = String(query).trim();
  const byId = snapshot.signatures_by_id || {};
  const byFp = snapshot.patches || {};
  const aliases = snapshot.aliases || {};

  const upper = q.toUpperCase();
  if (byId[upper]) return byId[upper];

  const cleanHex = q.replace(/^sha256:/i, "").toLowerCase();
  if (/^[0-9a-f]{64}$/.test(cleanHex) && byFp[cleanHex]) return byFp[cleanHex];

  const mapped = aliases[q.toLowerCase()];
  if (mapped && byFp[mapped]) return byFp[mapped];

  for (const rec of Object.values(byId)) {
    const tax = rec.taxonomy || {};
    const allIds = [
      ...(tax.cve_ids || []),
      ...(tax.ghsa_ids || []),
      ...(tax.advisory_ids || []),
      ...(tax.mitre_attack_ids || []),
      ...(tax.mitre_atlas_ids || []),
    ];
    if (allIds.some((t) => String(t).toLowerCase() === q.toLowerCase())) {
      return rec;
    }
  }
  return null;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestHead() {
  return new Response(null, { status: 200, headers: JSON_HEADERS });
}

export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  return new Response(
    JSON.stringify({
      name: SERVER_INFO.name,
      version: SERVER_INFO.version,
      protocol: PROTOCOL_VERSION,
      transport: "streamable-http",
      endpoint: `${url.origin}/mcp`,
      tools: TOOLS.map((t) => t.name),
    }, null, 2),
    { status: 200, headers: JSON_HEADERS }
  );
}

export async function onRequestPost(context) {
  const bodyRead = await readBoundedBody(context.request);
  if (!bodyRead.ok) {
    return jsonRpcError(null, -32600, "Request body exceeds 16384 byte limit", 413);
  }

  let rpc;
  try {
    rpc = JSON.parse(bodyRead.text);
  } catch {
    return jsonRpcError(null, -32700, "Parse error", 400);
  }

  const { id, method, params } = rpc || {};
  if (method === "initialize") {
    return jsonRpcResult(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
  }
  if (method === "notifications/initialized") {
    return new Response(null, { status: 202, headers: CORS_HEADERS });
  }
  if (method === "ping") {
    return jsonRpcResult(id, {});
  }
  if (method === "tools/list") {
    return jsonRpcResult(id, { tools: TOOLS });
  }
  if (method !== "tools/call") {
    return jsonRpcError(id, -32601, `Method not found: ${method}`);
  }

  const toolName = params?.name;
  const args = params?.arguments || {};
  const snapshot = await loadSnapshot(context.env);

  if (toolName === "fmagenticl_lookup_signature") {
    const match = lookupInSnapshot(snapshot, args.query);
    const payload = match
      ? { status: "MATCH_FOUND", signature: match, references: match.references || [] }
      : { status: "NOT_FOUND", deterministic_miss: true };
    return jsonRpcResult(id, { content: [{ type: "text", text: JSON.stringify(payload) }] });
  }

  if (toolName === "fmagenticl_list_signatures") {
    const byId = snapshot?.signatures_by_id || {};
    const limit = Math.max(1, Math.min(Number(args.limit || 50), 200));
    const results = [];
    for (const sig of Object.values(byId)) {
      if (args.confidence_tier && sig.confidence_tier !== args.confidence_tier) continue;
      if (args.threat_category && sig.threat_category !== args.threat_category) continue;
      if (args.severity && sig.severity !== args.severity) continue;
      if (args.surface && sig.observable?.surface !== args.surface) continue;
      results.push({
        id: sig.id,
        confidence_tier: sig.confidence_tier,
        threat_category: sig.threat_category,
        severity: sig.severity,
        title: sig.title,
        surface: sig.observable?.surface,
        references: sig.references || [],
      });
      if (results.length >= limit) break;
    }
    return jsonRpcResult(id, {
      content: [{ type: "text", text: JSON.stringify({ status: "OK", count: results.length, signatures: results }) }],
    });
  }

  if (toolName === "fmagenticl_resolve") {
    let match = null;
    for (const candidate of [args.fingerprint, args.target, args.raw_error]) {
      if (!candidate) continue;
      const m = TOKEN_EXTRACT_RE.exec(String(candidate));
      if (m) {
        match = lookupInSnapshot(snapshot, m[1]);
        if (match) break;
      }
    }
    const payload = match
      ? { status: "RESOLVED", signature: match, patch: match, references: match.references || [] }
      : { status: "UNRESOLVED", deterministic_miss: true, cacheable: true };
    return jsonRpcResult(id, { content: [{ type: "text", text: JSON.stringify(payload) }] });
  }

  return jsonRpcError(id, -32602, `Unknown tool: ${toolName}`);
}
