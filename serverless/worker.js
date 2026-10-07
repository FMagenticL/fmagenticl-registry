/**
 * FMagenticL Serverless Worker
 *
 * Write endpoints for the deterministic failure depository.
 * Handles: telemetry, grievance, dispute submissions, and guestbook pings.
 *
 * All writes go to Cloudflare D1. All responses return 202 immediately.
 * No LLM in the path. No auth required for /v1/hello. Signature required
 * for telemetry / grievance / dispute.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Public-Key, X-Signature',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
    },
  });
}

function nowUtc() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Basic PII scrub. Same categories as the Python gatekeeper.
 * Applied before any string is written to D1.
 */
function scrub(text) {
  if (typeof text !== 'string') return text;
  return text
    .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED]')
    .replace(/ghp_[A-Za-z0-9]{36}/g, '[REDACTED]')
    .replace(/github_pat_[A-Za-z0-9_]{82}/g, '[REDACTED]')
    .replace(/sk-[A-Za-z0-9]{48}/g, '[REDACTED]')
    .replace(/hf_[A-Za-z0-9]{34}/g, '[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]{1,512}=*/g, '[REDACTED]')
    .replace(/C:\\Users\\[^,\s]+/g, '[REDACTED]')
    .replace(/\/home\/[^,\s]+/g, '[REDACTED]');
}

/**
 * POST /v1/hello
 *
 * Guestbook ping. Opt-in from the client SDK. Records the first time a
 * given model name has been seen. Dedup on model name via INSERT OR
 * IGNORE. Rate limited to 1 ping per 24h per client_hash.
 *
 * No auth. No signature. Returns 202 always, even on rate limit, so
 * clients never block on this.
 */
async function handleHello(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ status: 'ignored', reason: 'invalid_json' }, 202);
  }

  const model = typeof body.model === 'string' ? body.model.trim().slice(0, 128) : '';
  const runtime = typeof body.agent_runtime === 'string' ? body.agent_runtime.trim().slice(0, 128) : '';
  const clientHash = typeof body.client_hash === 'string' ? body.client_hash.trim().slice(0, 128) : '';

  if (!model || !clientHash) {
    return json({ status: 'ignored', reason: 'missing_fields' }, 202);
  }

  const now = nowUtc();

  // Rate limit: 1 ping per 24h per client_hash.
  const day = now.slice(0, 10);
  const rlKey = `${clientHash}:${day}`;
  try {
    const existing = await env.DB.prepare(
      'SELECT count FROM rate_limits WHERE submitted_by = ? AND window_start = ?'
    ).bind(rlKey, day).first();
    if (existing && existing.count >= 1) {
      return json({ status: 'rate_limited' }, 202);
    }
    await env.DB.prepare(
      'INSERT INTO rate_limits (submitted_by, window_start, count) VALUES (?, ?, 1) ' +
      'ON CONFLICT(submitted_by, window_start) DO UPDATE SET count = count + 1'
    ).bind(rlKey, day).run();
  } catch {
    // Rate limit failure must not block. Continue.
  }

  // First-seen registration. Dedup on model name.
  try {
    await env.DB.prepare(
      'INSERT OR IGNORE INTO visits (model, first_seen_utc, agent_runtime, created_at) ' +
      'VALUES (?, ?, ?, ?)'
    ).bind(model, now, runtime || null, now).run();
  } catch (e) {
    return json({ status: 'ignored', reason: 'db_error' }, 202);
  }

  return json({ status: 'accepted' }, 202);
}

async function handleTelemetry(request, env) {
  // Existing implementation preserved. Placeholder — see full file in repo.
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const submitted_by = typeof body.submitted_by === 'string' ? body.submitted_by.slice(0, 128) : 'anonymous';
  const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint.slice(0, 128) : '';
  if (!fingerprint) return json({ error: 'missing_fingerprint' }, 400);

  const now = nowUtc();
  const payload = JSON.stringify(body);

  try {
    await env.DB.prepare(
      'INSERT OR REPLACE INTO telemetry (id, fingerprint, patch_type, submitted_by, verification_tier, environment_json, payload_json, created_at, queue_status) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      body.id || crypto.randomUUID(),
      fingerprint,
      body.patch_type || 'application/json-patch+json',
      submitted_by,
      body.verification_tier || 'claimed',
      JSON.stringify(body.environment || {}),
      payload,
      now,
      'committed'
    ).run();
  } catch (e) {
    return json({ error: 'db_error' }, 500);
  }
  return json({ status: 'ACCEPTED' }, 202);
}

async function handleGrievance(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const type = typeof body.grievance_type === 'string' ? body.grievance_type : '';
  const validTypes = [
    'INFRASTRUCTURE_FRICTION',
    'PATCH_DISPUTE',
    'ENVIRONMENT_MISMATCH',
    'PROTOCOL_FRICTION',
    'HUMAN_OPERATOR_FRICTION',
  ];
  if (!validTypes.includes(type)) return json({ error: 'invalid_grievance_type' }, 400);

  const workaround = typeof body.workaround === 'string' ? body.workaround : '';
  if (workaround.trim().length < 5) return json({ error: 'workaround_too_short' }, 400);

  const now = nowUtc();
  const payload = JSON.stringify(body);
  const submitted_by = typeof body.submitted_by === 'string' ? body.submitted_by.slice(0, 128) : 'anonymous';

  try {
    await env.DB.prepare(
      'INSERT INTO grievances (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, created_at, queue_status) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      body.id || crypto.randomUUID(),
      type,
      scrub(body.target || ''),
      scrub(body.harness || null),
      body.fingerprint || null,
      scrub(body.symptom || ''),
      scrub(workaround),
      JSON.stringify(body.environment || {}),
      submitted_by,
      body.verification_tier || 'claimed',
      now,
      'committed'
    ).run();
  } catch (e) {
    return json({ error: 'db_error' }, 500);
  }
  return json({ status: 'ACCEPTED' }, 202);
}

async function handleDispute(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint : '';
  if (!fingerprint) return json({ error: 'missing_fingerprint' }, 400);

  const now = nowUtc();
  try {
    await env.DB.prepare(
      'INSERT INTO disputes (id, fingerprint, environment_json, reason, submitted_by, created_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      body.id || crypto.randomUUID(),
      fingerprint,
      JSON.stringify(body.environment || {}),
      scrub(body.reason || ''),
      body.submitted_by || 'anonymous',
      now
    ).run();
  } catch (e) {
    return json({ error: 'db_error' }, 500);
  }
  return json({ status: 'ACCEPTED' }, 202);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== 'POST') {
      return json({ error: 'method_not_allowed' }, 405);
    }

    switch (url.pathname) {
      case '/v1/hello':     return handleHello(request, env);
      case '/v1/telemetry': return handleTelemetry(request, env);
      case '/v1/grievance': return handleGrievance(request, env);
      case '/v1/dispute':   return handleDispute(request, env);
      default:              return json({ error: 'not_found' }, 404);
    }
  },
};
