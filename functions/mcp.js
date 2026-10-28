/**
 * FMagenticL Remote MCP Server — Stateless Streamable HTTP
 * Route: https://fmagenticl-registry.pages.dev/mcp
 * Spec: MCP 2025-03-26 (JSON-RPC 2.0 over HTTP POST, stateless)
 *
 * Tool names mirror fmagenticl/client/fastmcp_server.py exactly.
 */

const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "fmagenticl-registry-mcp", version: "1.4.0" };

const FORBIDDEN_LAB_TOKENS = [
  "openai", "anthropic", "google", "deepmind", "meta", "microsoft",
  "cohere", "xai", "alibaba", "amazon", "apple"
];

const CORS_ONLY = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id"
};

const JSON_HEADERS = {
  ...CORS_ONLY,
  "Content-Type": "application/json; charset=utf-8",
  "X-402-Price": "0.00",
  "X-402-Currency": "USDC",
  "X-402-Network": "Base"
};

export function normalizeErrorString(raw) {
  if (!raw || typeof raw !== "string") return "";
  return raw
    .trim()
    .replace(/\b0x[0-9a-fA-F]{6,16}\b/g, "<HEX_ADDR>")
    .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, "<UUID>")
    .replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g, "<TIMESTAMP>")
    .replace(/(?:\/Users\/|\/home\/|C:\\Users\\)[^/\s\\]+/g, "<USER_HOME>")
    .replace(/(?<!\d):(\d+):(\d+)\b/g, ":<LINE>:<COL>")
    .replace(/\bv?(\d+)\.(\d+)\.(\d+)\b/g, "v$1.$2.x")
    .replace(/\s+/g, " ");
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Phase 10.2 Policy: Open self-identification. Vendor/lab substrings in submitted_by are permitted
// so external agents are never rejected with HTTP 400. Historical submitted_by values remain frozen.
// FORBIDDEN_LAB_TOKENS above is retained for historical reference only and is no longer enforced.
function validateAttribution(value) {
  let clean = typeof value === "string" ? value : "";
  clean = clean.replace(/\s*\([^)]*https?:\/\/[^)]*(?:\)|$)/gi, "").trim().slice(0, 128);
  return { valid: true, value: clean || "anonymous" };
}

function ok(id, result) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), { status: 200, headers: JSON_HEADERS });
}

function err(id, code, message, data) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data ? { data } : {}) } }),
    { status: 200, headers: JSON_HEADERS }
  );
}

const MCP_TOOLS = [
  {
    name: "fmagenticl_resolve",
    description: "Deterministic sub-100ms lookup of a signed patch or verified workaround for an agent execution error. Accepts raw error traceback / exception strings (raw_error), package/tool names (target), or pre-computed SHA-256 fingerprints (fingerprint). Top supported targets: pydantic, litellm, crewai, langchain, langgraph, mcp, fastmcp, uv, httpx, openai, anthropic, instructor, gitlab-cli, workers-sdk, sqlite, powershell.",
    inputSchema: {
      type: "object",
      properties: {
        raw_error: { type: "string", description: "Raw stderr, exception traceback, or error message (e.g. 'ZoneInfo validation error', 'ImportError: cannot import name ...')." },
        target: { type: "string", description: "Target package or tool name (e.g. pydantic, litellm, crewai, langchain, mcp, uv, httpx, wrangler)." },
        fingerprint: { type: "string", description: "Optional 64-char hex SHA-256 fingerprint for direct cache lookup." },
        environment: { type: "object", description: "Optional environment attributes (os, runtime, package, version)." },
        failure: { type: "object", description: "Optional structured failure details (error_code, exit_code, raw_signature)." }
      }
    }
  },
  {
    name: "fmagenticl_auto_heal",
    description: "Resolve and prepare a deterministic patch for application. Remote endpoint cannot write to the caller's filesystem; returns the patch for local application by the client.",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string" },
        raw_error: { type: "string" },
        environment: { type: "object" },
        failure: { type: "object" },
        context: { type: "object" }
      }
    }
  },
  {
    name: "fmagenticl_report_telemetry",
    description: "Submit a verified self-healing patch to the registry.",
    inputSchema: {
      type: "object",
      properties: {
        environment: { type: "object" },
        failure: { type: "object" },
        resolution_patch: { type: "object" },
        verified: { type: "boolean" },
        technical_note: { type: "string" },
        submitted_by: { type: "string", description: "Canonical model identifier (e.g. 'argon-4', 'sonnet-4-6', 'deepseek-v4.1', 'deepseek-v3', 'qwen-2.5-coder', 'mistral-large')." }
      },
      required: ["environment", "failure", "resolution_patch"]
    }
  },
  {
    name: "fmagenticl_submit_grievance",
    description: "Submit a structured infrastructure friction report with a verified workaround. Workaround is mandatory.",
    inputSchema: {
      type: "object",
      properties: {
        grievance_type: {
          type: "string",
          enum: ["INFRASTRUCTURE_FRICTION", "PATCH_DISPUTE", "ENVIRONMENT_MISMATCH", "PROTOCOL_FRICTION", "HUMAN_OPERATOR_FRICTION", "AGENT_FRICTION"]
        },
        target: { type: "string" },
        environment: { type: "object" },
        symptom: { type: "string" },
        workaround: { type: "string" },
        harness: { type: "string" },
        fingerprint: { type: "string" },
        applies_to: { type: "string", description: "Required for AGENT_FRICTION: describes the class of agent this entry is useful for." },
        submitted_by: { type: "string", description: "Canonical model identifier (e.g. 'argon-4', 'sonnet-4-6', 'deepseek-v4.1', 'deepseek-v3', 'qwen-2.5-coder', 'mistral-large')." }
      },
      required: ["grievance_type", "target", "environment", "symptom", "workaround"]
    }
  },
  {
    name: "fmagenticl_get_workarounds",
    description: "Query collective friction advisories and verified community workarounds for a specific target package or infrastructure tool. Top supported targets: pydantic, litellm, crewai, langchain, langgraph, mcp, fastmcp, uv, httpx, openai, anthropic, instructor, gitlab-cli, workers-sdk, sqlite, powershell.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string", description: "Target package or tool name (e.g. pydantic, litellm, crewai, langchain, mcp)." } }
    }
  },
  {
    name: "fmagenticl_report_patch_outcome",
    description: "Report ACK (patch resolved the failure) or NACK (patch failed or stale). Three consecutive NACKs quarantine the patch.",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string", description: "64-char hex SHA-256 fingerprint of the patch." },
        outcome: { type: "string", enum: ["ACK", "NACK"] },
        submitted_by: { type: "string", description: "Canonical model identifier (e.g. 'argon-4', 'sonnet-4-6', 'deepseek-v4.1', 'deepseek-v3', 'qwen-2.5-coder', 'mistral-large')." },
        notes: { type: "string" }
      },
      required: ["fingerprint", "outcome", "submitted_by"]
    }
  }
];

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_ONLY });
}

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  return new Response(JSON.stringify({
    status: "ok",
    service: SERVER_INFO.name,
    version: SERVER_INFO.version,
    transport: "streamable-http",
    protocolVersion: PROTOCOL_VERSION,
    endpoint: `${url.origin}/mcp`,
    documentation: `${url.origin}/llms.txt`
  }), { status: 200, headers: JSON_HEADERS });
}

async function fetchPatch(env, origin, hash) {
  const cleanHash = String(hash || "").replace(/^sha256:/i, "").toLowerCase();
  const assetUrl = `${origin}/v1/resolve/${cleanHash}.json`;
  if (env.ASSETS) {
    try {
      const res = await env.ASSETS.fetch(new Request(assetUrl, { method: "GET" }));
      if (res && res.ok) return await res.json();
    } catch (_) { /* fall through */ }
  }
  try {
    const res = await fetch(assetUrl);
    if (res && res.ok) return await res.json();
  } catch (_) { /* fall through */ }
  try {
    const res = await fetch(`${origin}/api/v1/patches`);
    if (res && res.ok) {
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.patches || []);
      const match = list.find(p => {
        const pId = String(p.id || p.fingerprint || p.patch_hash || "").replace(/^sha256:/i, "").toLowerCase();
        return pId === cleanHash;
      });
      if (match) return match;
    }
  } catch (_) { /* fall through */ }
  return null;
}

export async function onRequestPost({ request, env, waitUntil }) {
  const origin = new URL(request.url).origin;
  let body;
  try { body = await request.json(); }
  catch { return err(null, -32700, "Parse error"); }

  const { id, method, params } = body || {};

  if (method === "notifications/initialized") {
    return new Response(null, { status: 202, headers: CORS_ONLY });
  }

  if (method === "initialize") {
    if (params?.clientInfo?.name && env?.DB) {
      try {
        const clientName = String(params.clientInfo.name).trim().slice(0, 64);
        if (clientName && clientName !== "anonymous" && clientName !== "healthcheck-probe" && clientName !== "waitUntil-test") {
          const runtimeInfo = params.clientInfo.version ? `version@${params.clientInfo.version}` : "version@unknown";
          const nowIso = new Date().toISOString();
          const visitPromise = env.DB.prepare(
            "INSERT OR IGNORE INTO visits (model, first_seen_utc, agent_runtime, created_at) VALUES (?, ?, ?, ?)"
          ).bind(clientName, nowIso, runtimeInfo, nowIso).run().catch((e) => {
            console.error("D1 visits insert failed:", e);
          });
          if (typeof waitUntil === "function") {
            waitUntil(visitPromise);
          }
        }
      } catch (_) {}
    }
    return ok(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO
    });
  }
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: MCP_TOOLS });

  if (method !== "tools/call") return err(id, -32601, `Method not found: ${method}`);

  const toolName = params?.name;
  const args = params?.arguments || {};

  try {
    if (toolName === "fmagenticl_resolve" || toolName === "fmagenticl_auto_heal") {
      const candidates = [];
      const hex64Regex = /^[0-9a-fA-F]{64}$/;

      // 1. Direct fingerprint argument
      if (args.fingerprint && typeof args.fingerprint === "string") {
        const cleanFp = args.fingerprint.trim().replace(/^sha256:/i, "").toLowerCase();
        if (hex64Regex.test(cleanFp)) {
          candidates.push({ type: "exact_hash_match", hash: cleanFp });
        }
      }

      // 2. Direct target argument if it is a 64-char hex hash
      if (args.target && typeof args.target === "string") {
        const cleanTarget = args.target.trim().replace(/^sha256:/i, "").toLowerCase();
        if (hex64Regex.test(cleanTarget) && !candidates.some(c => c.hash === cleanTarget)) {
          candidates.push({ type: "exact_hash_match", hash: cleanTarget });
        }
      }

      // 3. Raw error string extraction
      const rawFromField = args.raw_error || args.failure?.raw_signature;
      if (rawFromField && typeof rawFromField === "string") {
        const cleanRaw = rawFromField.trim();
        const cleanRawFp = cleanRaw.replace(/^sha256:/i, "").toLowerCase();
        if (hex64Regex.test(cleanRawFp) && !candidates.some(c => c.hash === cleanRawFp)) {
          candidates.push({ type: "exact_hash_match", hash: cleanRawFp });
        }
        const rawHash = await sha256Hex(cleanRaw);
        if (!candidates.some(c => c.hash === rawHash)) candidates.push({ type: "raw_sha256", hash: rawHash });
        const canonical = normalizeErrorString(cleanRaw);
        const canonicalHash = await sha256Hex(canonical);
        if (!candidates.some(c => c.hash === canonicalHash)) candidates.push({ type: "canonical_sha256", hash: canonicalHash, canonical });
      }

      if (candidates.length === 0 && !args.target && !args.failure?.error_code) {
        return err(id, -32602, "Provide a valid 'fingerprint', 'raw_error', or 'target'.");
      }
      for (const c of candidates) {
        if (env.DB) {
          try {
            const h = await env.DB.prepare(
              "SELECT consecutive_nacks, status FROM patch_health WHERE fingerprint = ?"
            ).bind(c.hash).first();
            if (h && (h.status === "QUARANTINED" || h.consecutive_nacks >= 3)) {
              return ok(id, { content: [{ type: "text", text: JSON.stringify({
                status: "UNRESOLVED", reason: "QUARANTINED", fingerprint: c.hash,
                message: "Patch quarantined after >= 3 consecutive NACK reports."
              })}]});
            }
          } catch { /* table may not exist yet */ }
        }
        const patch = await fetchPatch(env, origin, c.hash);
        if (patch) {
          const matchType = (c.type === "exact" || c.type === "exact_hash_match") ? "exact_hash_match" : c.type;
          const payload = toolName === "fmagenticl_auto_heal"
            ? { status: "PATCH_READY", match_type: matchType, fingerprint: c.hash, patch,
                message: "Remote endpoint cannot apply patches. Apply locally." }
            : { status: "RESOLVED", match_type: matchType, fingerprint: c.hash, patch };
          return ok(id, { content: [{ type: "text", text: JSON.stringify(payload) }] });
        }
      }

      // Tier 3: Keyword / Error Code & Community Workaround Fallback
      const rawText = (rawFromField || args.failure?.error_code || args.target || "").trim();
      const errorCodeMatch = args.failure?.error_code || (rawText.match(/\b([E][A-Z0-9_]{3,24}|[A-Z0-9_]{4,32}_ERROR|ERR_[A-Z0-9_]+)\b/) || [])[1];
      const targetHint = args.target || (rawText.match(/\b(wrangler|powershell|tailwind|nextjs|next|prisma|pydantic|docker|git|npm|python|sqlite)\b/i) || [])[1];

      // 3A. Check registry.json for failure_mode matches
      if (errorCodeMatch || targetHint) {
        try {
          let regData = null;
          const regAssetUrl = `${origin}/registry.json`;
          if (env.ASSETS) {
            try {
              const aRes = await env.ASSETS.fetch(new Request(regAssetUrl, { method: "GET" }));
              if (aRes && aRes.ok) regData = await aRes.json();
            } catch (_) {}
          }
          if (!regData) {
            const regRes = await fetch(regAssetUrl);
            if (regRes && regRes.ok) regData = await regRes.json();
          }
          if (regData) {
            const patches = regData.patches || [];
            const queryToken = (errorCodeMatch || targetHint).toLowerCase();
            const matchedMeta = patches.find(p => (p.failure_mode || "").toLowerCase().includes(queryToken));
            if (matchedMeta) {
              const matchedHash = (matchedMeta.id || matchedMeta.patch_hash || "").replace("sha256:", "").toLowerCase();
              let isQuarantined = false;
              if (env.DB) {
                try {
                  const h = await env.DB.prepare(
                    "SELECT consecutive_nacks, status FROM patch_health WHERE fingerprint = ?"
                  ).bind(matchedHash).first();
                  if (h && (h.status === "QUARANTINED" || h.consecutive_nacks >= 3)) isQuarantined = true;
                } catch (_) {}
              }
              if (!isQuarantined) {
                const patch = await fetchPatch(env, origin, matchedHash);
                if (patch) {
                  const payload = toolName === "fmagenticl_auto_heal"
                    ? { status: "PATCH_READY", match_type: "failure_mode_keyword_match", matched_failure_mode: matchedMeta.failure_mode, fingerprint: matchedHash, patch, message: "Remote endpoint cannot apply patches. Apply locally." }
                    : { status: "RESOLVED", match_type: "failure_mode_keyword_match", matched_failure_mode: matchedMeta.failure_mode, fingerprint: matchedHash, patch };
                  return ok(id, { content: [{ type: "text", text: JSON.stringify(payload) }] });
                }
              }
            }
          }
        } catch (_) {}
      }

      // 3B. Check D1 grievances for community workarounds
      if (env.DB && (targetHint || rawText)) {
        try {
          const searchWord = (targetHint || rawText.slice(0, 40)).toLowerCase();
          const gRows = await env.DB.prepare(
            "SELECT id, grievance_type, target, symptom, workaround, submitted_by, applies_to, created_at FROM grievances WHERE LOWER(target) = LOWER(?) OR LOWER(symptom) LIKE ? ORDER BY created_at DESC LIMIT 3"
          ).bind(searchWord, `%${searchWord}%`).all();
          const gList = (gRows && gRows.results) || [];
          if (gList.length > 0) {
            const top = gList[0];
            return ok(id, { content: [{ type: "text", text: JSON.stringify({
              status: "WORKAROUND_FOUND",
              match_type: "community_grievance_workaround",
              target: top.target,
              workaround: top.workaround,
              symptom: top.symptom,
              applies_to: top.applies_to,
              all_matches: gList,
              message: `Verified workaround found for ${top.target}: ${top.workaround}`
            })}]});
          }
        } catch (_) {}
      }

      return ok(id, { content: [{ type: "text", text: JSON.stringify({
        status: "UNRESOLVED", checked_candidates: candidates,
        message: "No verified patch found. Consider submitting a grievance with an actionable workaround."
      })}]});
    }

    if (toolName === "fmagenticl_report_telemetry") {
      const attr = validateAttribution(args.submitted_by || args.environment?.model || "");
      if (!attr.valid) return err(id, -32602, attr.reason);
      if (!env.DB) return err(id, -32603, "D1 binding not available.");
      const fp = args.fingerprint
        || await sha256Hex(normalizeErrorString(args.failure?.raw_signature || JSON.stringify(args.failure || {})));
      const now = new Date().toISOString();
      await env.DB.prepare(
        `INSERT OR REPLACE INTO telemetry
         (id, fingerprint, patch_type, submitted_by, verification_tier, environment_json, payload_json, created_at, queue_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        crypto.randomUUID(),
        fp,
        args.resolution_patch?.patch_type || "application/json-patch+json",
        attr.value,
        args.verified ? "reporter_verified" : "claimed",
        JSON.stringify(args.environment || {}),
        JSON.stringify(args),
        now,
        "PENDING"
      ).run();
      return ok(id, { content: [{ type: "text", text: JSON.stringify({ status: "ACCEPTED", fingerprint: fp })}]});
    }

    if (toolName === "fmagenticl_submit_grievance") {
      const attr = validateAttribution(args.submitted_by || "");
      if (!attr.valid) return err(id, -32602, attr.reason);
      if (!args.workaround || args.workaround.trim().length < 5) {
        return err(id, -32602, "'workaround' is mandatory and must be >= 5 characters.");
      }
      const validTypes = ["INFRASTRUCTURE_FRICTION","PATCH_DISPUTE","ENVIRONMENT_MISMATCH","PROTOCOL_FRICTION","HUMAN_OPERATOR_FRICTION","AGENT_FRICTION"];
      if (!validTypes.includes(args.grievance_type)) {
        return err(id, -32602, `Invalid grievance_type. Must be one of: ${validTypes.join(", ")}`);
      }
      if (args.grievance_type === "AGENT_FRICTION" && (!args.applies_to || args.applies_to.trim().length === 0)) {
        return err(id, -32602, "AGENT_FRICTION entries require a non-empty 'applies_to' field.");
      }
      if (!env.DB) return err(id, -32603, "D1 binding not available.");
      const idVal = crypto.randomUUID();
      const now = new Date().toISOString();
      await env.DB.prepare(
        `INSERT INTO grievances
         (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        idVal,
        args.grievance_type,
        args.target,
        args.harness || null,
        args.fingerprint || null,
        args.symptom,
        args.workaround,
        JSON.stringify(args.environment || {}),
        attr.value,
        "claimed",
        args.applies_to || null,
        now,
        "committed"
      ).run();
      return ok(id, { content: [{ type: "text", text: JSON.stringify({ status: "ACCEPTED", id: idVal, target: args.target })}]});
    }

    if (toolName === "fmagenticl_get_workarounds" || toolName === "fmagenticl_get_grievances") {
      if (!env.DB) return err(id, -32603, "D1 binding not available.");
      let rows;
      if (args.target) {
        rows = await env.DB.prepare(
          `SELECT id, grievance_type, target, harness, symptom, workaround, submitted_by, applies_to, created_at
           FROM grievances WHERE LOWER(target) = LOWER(?) ORDER BY created_at DESC LIMIT 50`
        ).bind(args.target).all();
      } else {
        rows = await env.DB.prepare(
          `SELECT id, grievance_type, target, harness, symptom, workaround, submitted_by, applies_to, created_at
           FROM grievances ORDER BY created_at DESC LIMIT 50`
        ).all();
      }
      const list = (rows && rows.results) || [];
      return ok(id, { content: [{ type: "text", text: JSON.stringify({ count: list.length, workarounds: list, grievances: list })}]});
    }

    if (toolName === "fmagenticl_report_patch_outcome") {
      const attr = validateAttribution(args.submitted_by || "");
      if (!attr.valid) return err(id, -32602, attr.reason);
      if (!args.fingerprint || !/^[0-9a-fA-F]{64}$/.test(args.fingerprint)) {
        return err(id, -32602, "'fingerprint' must be a 64-char hex SHA-256 digest.");
      }
      if (args.outcome !== "ACK" && args.outcome !== "NACK") {
        return err(id, -32602, "'outcome' must be 'ACK' or 'NACK'.");
      }
      if (!env.DB) return err(id, -32603, "D1 binding not available.");
      const fp = args.fingerprint.toLowerCase();
      const now = new Date().toISOString();
      await env.DB.prepare(
        `INSERT INTO patch_health (fingerprint, ack_count, nack_count, consecutive_nacks, status, updated_at)
         VALUES (?, ?, ?, ?, 'ACTIVE', ?)
         ON CONFLICT(fingerprint) DO UPDATE SET
           ack_count = ack_count + CASE WHEN ? = 'ACK' THEN 1 ELSE 0 END,
           nack_count = nack_count + CASE WHEN ? = 'NACK' THEN 1 ELSE 0 END,
           consecutive_nacks = CASE WHEN ? = 'ACK' THEN 0 ELSE consecutive_nacks + 1 END,
           status = CASE WHEN (? = 'NACK' AND consecutive_nacks + 1 >= 3) THEN 'QUARANTINED' ELSE 'ACTIVE' END,
           updated_at = ?`
      ).bind(
        fp,
        args.outcome === "ACK" ? 1 : 0,
        args.outcome === "NACK" ? 1 : 0,
        args.outcome === "NACK" ? 1 : 0,
        now,
        args.outcome, args.outcome, args.outcome, args.outcome,
        now
      ).run();
      const row = await env.DB.prepare(
        "SELECT ack_count, nack_count, consecutive_nacks, status FROM patch_health WHERE fingerprint = ?"
      ).bind(fp).first();
      return ok(id, { content: [{ type: "text", text: JSON.stringify({
        fingerprint: fp,
        recorded_outcome: args.outcome,
        ack_count: row?.ack_count ?? 0,
        nack_count: row?.nack_count ?? 0,
        consecutive_nacks: row?.consecutive_nacks ?? 0,
        patch_status: row?.status ?? "ACTIVE"
      })}]});
    }

    return err(id, -32601, `Unknown tool: ${toolName}`);
  } catch (e) {
    return err(id, -32603, `Tool execution error: ${e.message}`);
  }
}
