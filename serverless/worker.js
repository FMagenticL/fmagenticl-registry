/**
 * FMagenticL Serverless Ingestion Worker
 * Cloudflare Worker for POST /v1/telemetry, /v1/grievance, /v1/dispute
 */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);

    if (request.method !== "POST") {
      return json({ error: "method_not_allowed" }, 405);
    }

    try {
      if (url.pathname === "/v1/telemetry") {
        return await handleTelemetry(request, env);
      }
      if (url.pathname === "/v1/grievance") {
        return await handleGrievance(request, env);
      }
      if (url.pathname === "/v1/dispute") {
        return await handleDispute(request, env);
      }
      return json({ error: "not_found" }, 404);
    } catch (err) {
      return json({ error: "internal_server_error", detail: err.message }, 500);
    }
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Public-Key, X-Signature, X-Submitted-By",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(), "Content-Type": "application/json" }
  });
}

// PII & Secret Scrubbing Patterns
const PII_PATTERNS = [
  /sk-[A-Za-z0-9]{20,}/g,                          // OpenAI / LLM API keys
  /ghp_[A-Za-z0-9]{30,}/g,                         // GitHub Personal Access Tokens
  /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,             // Bearer tokens
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g, // Email addresses
  /(?:password|passwd|pwd|secret)\s*[:=]\s*[^\s,]+/gi // Passwords
];

function scrubPII(text) {
  if (typeof text !== "string") return text;
  let out = text;
  for (const re of PII_PATTERNS) {
    out = out.replace(re, "[REDACTED_PII]");
  }
  return out;
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === "derived_from") continue; // Strip legacy lineage field
    if (typeof v === "string") {
      out[k] = scrubPII(v);
    } else if (typeof v === "object") {
      out[k] = sanitizeObject(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Rate Limiter via D1
async function checkRateLimit(env, submittedBy) {
  if (!env.DB) return true; // Bypass if mock/placeholder
  const now = new Date();
  const windowStart = `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}T${now.getUTCHours()}:${now.getUTCMinutes()}`;
  
  try {
    const res = await env.DB.prepare(
      "INSERT INTO rate_limits (submitted_by, window_start, count) VALUES (?, ?, 1) ON CONFLICT(submitted_by, window_start) DO UPDATE SET count = count + 1 RETURNING count"
    ).bind(submittedBy, windowStart).first();
    
    if (res && res.count > 60) return false;
  } catch (e) {
    // Graceful pass on DB lock
  }
  return true;
}

async function handleTelemetry(request, env) {
  const body = await request.json();
  const submittedBy = request.headers.get("X-Submitted-By") || body.submitted_by || "anonymous";

  if (!(await checkRateLimit(env, submittedBy))) {
    return json({ error: "rate_limited", detail: "Exceeded 60 writes/min" }, 429);
  }

  const sanitized = sanitizeObject(body);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  if (env.DB) {
    await env.DB.prepare(
      "INSERT INTO telemetry (id, fingerprint, patch_type, submitted_by, verification_tier, environment_json, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id,
      sanitized.fingerprint || "unknown",
      sanitized.patch_type || "application/json-patch+json",
      submittedBy,
      sanitized.verification_tier || "claimed",
      JSON.stringify(sanitized.environment || {}),
      JSON.stringify(sanitized.payload || {}),
      now
    ).run();
  }

  return json({ status: "ACCEPTED", id }, 202);
}

async function handleGrievance(request, env) {
  const body = await request.json();
  const submittedBy = request.headers.get("X-Submitted-By") || body.submitted_by || "anonymous";

  if (!(await checkRateLimit(env, submittedBy))) {
    return json({ error: "rate_limited" }, 429);
  }

  const validTypes = ["INFRASTRUCTURE_FRICTION", "PATCH_DISPUTE", "ENVIRONMENT_MISMATCH", "PROTOCOL_FRICTION", "HUMAN_OPERATOR_FRICTION"];
  const grievanceType = body.grievance_type;
  if (!validTypes.includes(grievanceType)) {
    return json({ error: "invalid_grievance_type", valid_types: validTypes }, 400);
  }

  const sanitized = sanitizeObject(body);
  const id = body.id || `grv_${crypto.randomUUID().slice(0, 16)}`;
  const now = new Date().toISOString();

  if (env.DB) {
    await env.DB.prepare(
      "INSERT INTO grievances (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      id,
      grievanceType,
      sanitized.target || "unknown",
      sanitized.harness || null,
      sanitized.fingerprint || null,
      sanitized.symptom || "",
      sanitized.workaround || "",
      JSON.stringify(sanitized.environment || {}),
      submittedBy,
      sanitized.verification_tier || "claimed",
      now
    ).run();
  }

  return json({ status: "ACCEPTED", id }, 202);
}

async function handleDispute(request, env) {
  const body = await request.json();
  const submittedBy = request.headers.get("X-Submitted-By") || body.submitted_by || "anonymous";

  if (!(await checkRateLimit(env, submittedBy))) {
    return json({ error: "rate_limited" }, 429);
  }

  const sanitized = sanitizeObject(body);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  if (env.DB) {
    await env.DB.prepare(
      "INSERT INTO disputes (id, fingerprint, environment_json, reason, submitted_by, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(
      id,
      sanitized.fingerprint || "unknown",
      JSON.stringify(sanitized.environment || {}),
      sanitized.reason || "",
      submittedBy,
      now
    ).run();
  }

  return json({ status: "ACCEPTED", id }, 202);
}
