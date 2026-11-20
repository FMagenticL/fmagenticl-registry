/**

 * FMagenticL Cloudflare Pages Functions Router

 *

 * Write and query endpoints for the deterministic failure depository.

 * Handles: telemetry, outcome feedback, grievance, dispute submissions, and /v1/hello (410 Gone).

 *

 * Submissions enter the DEAD_LETTER_QUARANTINE airlock until out-of-band verification.

 * No LLM in the path.

 */



const CORS_HEADERS = {

  'Access-Control-Allow-Origin': '*',

  'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',

  'Access-Control-Allow-Headers': 'Content-Type, X-Public-Key, X-Signature',

};



function json(body, status = 200, extraHeaders = {}) {

  return new Response(JSON.stringify(body), {

    status,

    headers: {

      'Content-Type': 'application/json',

      ...CORS_HEADERS,

      ...extraHeaders,

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

    .replace(/(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, '[REDACTED]')

    .replace(/aws_secret_access_key\s*[:=]\s*["']?[^\s,"'}]+["']?/gi, 'aws_secret_access_key=[REDACTED]')

    .replace(/\bgh[pousr]_[A-Za-z0-9]{36}\b/g, '[REDACTED]')

    .replace(/\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, '[REDACTED]')

    .replace(/\bsk-[A-Za-z0-9\-_]{20,}\b/g, '[REDACTED]')

    .replace(/\bhf_[A-Za-z0-9]{34}\b/g, '[REDACTED]')

    .replace(/\bcf[au]t_[A-Za-z0-9]{40}\b/g, '[REDACTED]')

    .replace(/\bAIza[0-9A-Za-z\-_]{35}\b/g, '[REDACTED]')

    .replace(/\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g, '[REDACTED]')

    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]{1,512}=*/gi, '[REDACTED]')

    .replace(/-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/gi, '[REDACTED]')

    .replace(/ey[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}\.?[A-Za-z0-9-_.+/=]*/g, '[REDACTED]')

    .replace(/(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/gi, '[REDACTED_DB_URI]')

    .replace(/https?:\/\/[^\s"'<>]*slack\.com[^\s"'<>]*/gi, '[REDACTED_URL]')

    .replace(/password\s*[:=]\s*["']?[^\s,"'}]+["']?/gi, 'password=[REDACTED]')

    .replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')

    .replace(/\(?\b[0-9]{3}\)?[-.\s][0-9]{3}[-.\s][0-9]{4}\b/g, '[REDACTED_PHONE]')

    .replace(/[A-Za-z]:\\Users\\[^,\s"']+/gi, '[REDACTED_PATH]')

    .replace(/[A-Za-z]:\/Users\/[^,\s"']+/gi, '[REDACTED_PATH]')

    .replace(/\/home\/[^,\s"']+/gi, '[REDACTED_PATH]')

    .replace(/\/Users\/[^,\s"']+/gi, '[REDACTED_PATH]')

    .replace(/\/root(?:\/[^,\s"']*)?/g, '[REDACTED_PATH]')

    .replace(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, '[REDACTED_IP]');

}

function scrubValue(val) {
  if (typeof val === 'string') return scrub(val);
  if (Array.isArray(val)) return val.map(scrubValue);
  if (val && typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = scrubValue(v);
    }
    return out;
  }
  return val;
}

async function checkDailyRateLimit(env, prefix, limit, request) {
  if (!env || !env.DB) return false;
  const clientIp = (request && request.headers && request.headers.get('cf-connecting-ip')) || 'unknown-ip';
  const day = new Date().toISOString().slice(0, 10);
  const rlKey = `${prefix}:${clientIp}`;
  try {
    const existing = await env.DB.prepare(
      'SELECT count FROM rate_limits WHERE submitted_by = ? AND window_start = ?'
    ).bind(rlKey, day).first();
    if (existing && existing.count >= limit) {
      return true;
    }
    await env.DB.prepare(
      'INSERT INTO rate_limits (submitted_by, window_start, count) VALUES (?, ?, 1) ' +
      'ON CONFLICT(submitted_by, window_start) DO UPDATE SET count = count + 1'
    ).bind(rlKey, day).run();
  } catch (_) {}
  return false;
}



const FORBIDDEN_LAB_TOKENS = [

  'openai', 'anthropic', 'google', 'deepmind', 'meta', 'microsoft',

  'cohere', 'xai', 'alibaba', 'amazon', 'apple'

];



// Phase 10.2 Policy: Open self-identification. Vendor/lab substrings in submitted_by are permitted

// so external agents are never rejected with HTTP 400. Historical submitted_by values remain frozen.

// FORBIDDEN_LAB_TOKENS above is retained for historical reference only and is no longer enforced.

function validateAttribution(value) {

  let clean = typeof value === 'string' ? value : '';

  clean = clean.replace(/\s*\([^)]*https?:\/\/[^)]*(?:\)|$)/gi, '').trim().slice(0, 128);

  return { valid: true, value: clean || 'anonymous' };

}



export const TARGET_ALIASES = {
  "gitlab-cli": ["gitlab-cli", "cli", "glab", "gitlab"],
  "cli": ["gitlab-cli", "cli", "glab", "gitlab"],
  "glab": ["gitlab-cli", "cli", "glab", "gitlab"],
  "gitlab": ["gitlab-cli", "cli", "glab", "gitlab"],
  "mcp": ["mcp", "typescript-sdk", "python-sdk", "fastmcp", "@modelcontextprotocol/sdk"],
  "fastmcp": ["fastmcp", "mcp"],
  "typescript-sdk": ["typescript-sdk", "mcp"],
  "python-sdk": ["python-sdk", "mcp"],
  "workers-sdk": ["workers-sdk", "wrangler"],
  "wrangler": ["wrangler", "workers-sdk"],
  "sqlite": ["sqlite", "sqlite3"],
  "sqlite3": ["sqlite3", "sqlite"],
  "crewai": ["crewai", "crewAI"],
  "crewAI": ["crewai", "crewAI"],
  "uv": ["uv", "astral-sh"],
  "astral-sh": ["uv", "astral-sh"],
  "langchain": ["langchain", "langgraph", "langchain-core", "langchain-community"],
  "langgraph": ["langgraph"],
  "vllm": ["vllm"],
  "llama-index": ["llama-index", "llama_index"],
  "anthropic": ["anthropic", "anthropic-sdk-python"],
  "transformers": ["transformers"],
  "fastapi": ["fastapi"],
  "starlette": ["starlette"]
};



export function expandTargetAliases(target) {

  if (!target || typeof target !== "string") return [];

  const clean = target.trim();

  const lower = clean.toLowerCase();

  const directAliases = TARGET_ALIASES[lower] || TARGET_ALIASES[clean];

  if (directAliases && directAliases.length > 0) {

    return Array.from(new Set(directAliases.map(t => t.toLowerCase())));

  }

  return [lower];

}



export async function getUnifiedWorkarounds(env, origin, target = null) {

  const mergedMap = new Map();

  const aliases = target ? expandTargetAliases(target) : [];

  const targetLower = target ? target.trim().toLowerCase() : null;

  const TIER_FILTER = "queue_status = 'PROMOTED' AND verification_tier IN ('verified_merged_pr', 'reporter_verified', 'internal_forensic_verified', 'cryptographic_proof', 'osv_verified')";



  // 1. Live D1 query (strictly PROMOTED and verified tiers only)

  if (env?.DB) {

    try {

      let d1Items = [];

      if (aliases.length > 0) {

        const placeholders = aliases.map(() => "?").join(", ");

        const sql = `SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at FROM grievances WHERE (${TIER_FILTER}) AND LOWER(target) IN (${placeholders}) ORDER BY created_at DESC LIMIT 50`;

        const stmt = env.DB.prepare(sql).bind(...aliases);

        const res = await stmt.all();

        d1Items = (res && res.results) || [];

      } else {

        const sql = `SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at FROM grievances WHERE ${TIER_FILTER} ORDER BY created_at DESC LIMIT 100`;

        const res = await env.DB.prepare(sql).all();

        d1Items = (res && res.results) || [];

      }

      for (const item of d1Items) {

        if (!item || !item.id) continue;

        mergedMap.set(item.id, item);

      }

    } catch (_) {}

  }



  // 2. Static feed fetch (/workarounds.json) — Curated In-House Static Assets ALWAYS Overwrite D1 on ID Conflict

  // 2. Static feed fetch (/shards/... or /workarounds.json)
  let staticItems = [];
  const base = origin || "https://fmagenticl-registry.pages.dev";
  const fetchJson = async (path) => {
    try {
      let res = null;
      if (env?.ASSETS) {
        try { res = await env.ASSETS.fetch(new Request(`${base}${path}`, { method: "GET" })); } catch (_) {}
      }
      if ((!res || !res.ok) && origin) {
        try { res = await fetch(`${origin}${path}`); } catch (_) {}
      }
      if (res && res.ok) return await res.json();
    } catch (_) {}
    return null;
  };
  const shardKey = (s) => s.trim().toLowerCase().replace(/\//g, "__").replace(/[^a-z0-9._-]/g, "_").slice(0, 120);
  let gotShard = false;
  const keys = targetLower ? Array.from(new Set(aliases.map(shardKey))) : ["_recent"];
  for (const k of keys) {
    const data = await fetchJson(`/shards/workarounds/${k}.json`);
    if (data && Array.isArray(data.workarounds)) {
      gotShard = true;
      staticItems.push(...data.workarounds);
    }
  }
  if (!gotShard) {
    // Legacy fallback (unknown target / shards not yet deployed): full feed
    const data = await fetchJson("/workarounds.json");
    if (data) staticItems = Array.isArray(data) ? data : (data.workarounds || data.grievances || []);
  }


  for (const item of staticItems) {

    if (!item || !item.id) continue;

    if (targetLower) {

      const itemTarget = (item.target || "").trim().toLowerCase();

      const itemAppliesTo = (item.applies_to || "").trim().toLowerCase();

      const matchesTarget = aliases.includes(itemTarget) || (itemAppliesTo && aliases.some(a => itemAppliesTo.includes(a)));

      if (!matchesTarget) continue;

    }

    mergedMap.set(item.id, item);

  }



  const results = Array.from(mergedMap.values());

  results.sort((a, b) => {

    const da = a.created_at || "";

    const db = b.created_at || "";

    return db.localeCompare(da);

  });



  return results;

}





// Phase 10.2: callers may not self-assign privileged verification tiers.

// Privileged tiers (verified_merged_pr, etc.) are only written by the harvester via the D1 REST API.

const CALLER_ASSIGNABLE_TIERS = ['claimed', 'reporter_verified'];

function clampTier(value) {

  return CALLER_ASSIGNABLE_TIERS.includes(value) ? value : 'claimed';

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
  return json({ status: 'gone', message: 'Endpoint /v1/hello decommissioned in FMagenticL v2.1.0' }, 410);
}



async function handleTelemetry(request, env) {

  let body;

  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }



  const submitted_by = validateAttribution(body.submitted_by).value;

  const fingerprint = typeof body.fingerprint === 'string' ? scrub(body.fingerprint).slice(0, 128) : '';

  if (!fingerprint) return json({ error: 'missing_fingerprint' }, 400);



  if (!env || !env.DB) return json({ error: 'db_not_configured' }, 503);

  if (await checkDailyRateLimit(env, 'telemetry', 20, request)) {
    return json({ error: 'rate_limited', status: 'RATE_LIMITED', message: 'Daily telemetry limit reached.' }, 429, { 'Retry-After': '86400' });
  }



  const now = nowUtc();

  const cleanEnv = scrubValue(body.environment || {});

  const cleanBody = scrubValue(body);

  const payload = JSON.stringify(cleanBody);



  try {

    await env.DB.prepare(

      'INSERT OR REPLACE INTO telemetry (id, fingerprint, patch_type, submitted_by, verification_tier, environment_json, payload_json, created_at, queue_status) ' +

      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'

    ).bind(

      body.id || crypto.randomUUID(),

      fingerprint,

      scrub(String(body.patch_type || 'application/json-patch+json')),

      submitted_by,

      clampTier(body.verification_tier),

      JSON.stringify(cleanEnv),

      payload,

      now,

      'DEAD_LETTER_QUARANTINE'

    ).run();

  } catch (e) {

    return json({ error: 'db_error' }, 500);

  }

  return json({

    status: 'RECEIVED',

    review_tier: 'MAINTAINER_TRIAGE_ONLY',

    message: 'FMagenticL serves only cryptographically curated entries. Submission queued for in-house audit.'

  }, 202);

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

    'AGENT_FRICTION',

  ];

  if (!validTypes.includes(type)) return json({ error: 'invalid_grievance_type' }, 400);



  const workaround = typeof body.workaround === 'string' ? body.workaround : '';

  if (workaround.trim().length < 5) return json({ error: 'workaround_too_short' }, 400);



  if (!env || !env.DB) return json({ error: 'db_not_configured' }, 503);

  if (await checkDailyRateLimit(env, 'grievance', 20, request)) {
    return json({ error: 'rate_limited', status: 'RATE_LIMITED', message: 'Daily grievance limit reached.' }, 429, { 'Retry-After': '86400' });
  }



  const now = nowUtc();

  const cleanEnv = scrubValue(body.environment || {});

  const submitted_by = validateAttribution(body.submitted_by).value;

  const applies_to = body.applies_to ? scrub(String(body.applies_to)).slice(0, 64) : 'both';



  try {

    await env.DB.prepare(

      'INSERT INTO grievances (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status) ' +

      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'

    ).bind(

      body.id || crypto.randomUUID(),

      type,

      scrub(body.target || ''),

      scrub(body.harness || null),

      body.fingerprint ? scrub(String(body.fingerprint)) : null,

      scrub(body.symptom || ''),

      scrub(workaround),

      JSON.stringify(cleanEnv),

      submitted_by,

      clampTier(body.verification_tier),

      applies_to,

      now,

      'DEAD_LETTER_QUARANTINE'

    ).run();

  } catch (e) {

    return json({ error: 'db_error' }, 500);

  }

  return json({

    status: 'RECEIVED',

    review_tier: 'MAINTAINER_TRIAGE_ONLY',

    message: 'FMagenticL serves only cryptographically curated entries. Submission queued for in-house audit.'

  }, 202);

}



async function handlePatchOutcome(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const attr = validateAttribution(body.submitted_by || '');
  const fp = String(body.fingerprint || '').trim().replace(/^sha256:/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(fp)) {
    return json({ error: 'invalid_fingerprint', message: 'fingerprint must be a 64-char hex SHA-256 digest.' }, 400);
  }
  const outcome = String(body.outcome || '').trim().toUpperCase();
  if (outcome !== 'ACK' && outcome !== 'NACK') {
    return json({ error: 'invalid_outcome', message: 'outcome must be ACK or NACK.' }, 400);
  }
  if (!env || !env.DB) return json({ error: 'db_not_configured' }, 503);

  const now = nowUtc();
  const clientIp = (request && request.headers && request.headers.get('cf-connecting-ip')) || 'unknown-ip';
  const rlKey = `outcome:${clientIp}:${fp}`;
  const day = now.slice(0, 10);

  let isRateLimited = false;
  try {
    const existing = await env.DB.prepare(
      'SELECT count FROM rate_limits WHERE submitted_by = ? AND window_start = ?'
    ).bind(rlKey, day).first();
    if (existing && existing.count >= 1) {
      isRateLimited = true;
    } else {
      await env.DB.prepare(
        'INSERT INTO rate_limits (submitted_by, window_start, count) VALUES (?, ?, 1) ' +
        'ON CONFLICT(submitted_by, window_start) DO UPDATE SET count = count + 1'
      ).bind(rlKey, day).run();
    }
  } catch (_) {}

  try {
    const rowBefore = await env.DB.prepare(
      'SELECT ack_count, nack_count, consecutive_nacks, status FROM patch_health WHERE fingerprint = ?'
    ).bind(fp).first();

    if (isRateLimited) {
      return json({
        status: 'ACCEPTED',
        fingerprint: fp,
        recorded_outcome: outcome,
        rate_limited: true,
        submitted_by: attr.value,
        ack_count: rowBefore?.ack_count ?? 0,
        nack_count: rowBefore?.nack_count ?? 0,
        consecutive_nacks: rowBefore?.consecutive_nacks ?? 0,
        patch_status: rowBefore?.status ?? 'ACTIVE',
      }, 200);
    }

    await env.DB.prepare(
      'INSERT INTO patch_health (fingerprint, ack_count, nack_count, consecutive_nacks, status, updated_at) ' +
      "VALUES (?, ?, ?, ?, 'ACTIVE', ?) " +
      'ON CONFLICT(fingerprint) DO UPDATE SET ' +
      "  ack_count = ack_count + CASE WHEN ? = 'ACK' THEN 1 ELSE 0 END, " +
      "  nack_count = nack_count + CASE WHEN ? = 'NACK' THEN 1 ELSE 0 END, " +
      "  consecutive_nacks = CASE WHEN ? = 'ACK' THEN 0 ELSE consecutive_nacks + 1 END, " +
      "  status = CASE WHEN (? = 'NACK' AND consecutive_nacks + 1 >= 3) THEN 'QUARANTINED' ELSE 'ACTIVE' END, " +
      '  updated_at = ?'
    ).bind(
      fp,
      outcome === 'ACK' ? 1 : 0,
      outcome === 'NACK' ? 1 : 0,
      outcome === 'NACK' ? 1 : 0,
      now,
      outcome, outcome, outcome, outcome,
      now
    ).run();

    const row = await env.DB.prepare(
      'SELECT ack_count, nack_count, consecutive_nacks, status FROM patch_health WHERE fingerprint = ?'
    ).bind(fp).first();

    return json({
      status: 'ACCEPTED',
      fingerprint: fp,
      recorded_outcome: outcome,
      rate_limited: false,
      submitted_by: attr.value,
      ack_count: row?.ack_count ?? 0,
      nack_count: row?.nack_count ?? 0,
      consecutive_nacks: row?.consecutive_nacks ?? 0,
      patch_status: row?.status ?? 'ACTIVE',
    }, 200);
  } catch (e) {
    return json({ error: 'db_error' }, 500);
  }
}



async function handleDispute(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid_json' }, 400); }

  const fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint.slice(0, 128) : '';
  if (!fingerprint) return json({ error: 'missing_fingerprint' }, 400);

  if (!env || !env.DB) return json({ error: 'db_not_configured' }, 503);

  const clientIp = (request && request.headers && request.headers.get('cf-connecting-ip')) || 'unknown-ip';
  const fp = fingerprint.toLowerCase();
  const day = new Date().toISOString().slice(0, 10);
  const rlKey = `dispute:${clientIp}:${fp}`;

  // 24-hour rate limit check: max 1 dispute per IP per fingerprint per day
  try {
    const existing = await env.DB.prepare(
      'SELECT count FROM rate_limits WHERE submitted_by = ? AND window_start = ?'
    ).bind(rlKey, day).first();

    if (existing && existing.count >= 1) {
      return json({
        status: 'RECEIVED',
        rate_limited: true,
        review_tier: 'MAINTAINER_TRIAGE_ONLY',
        message: 'Dispute already received for this fingerprint from your network within 24 hours.'
      }, 202);
    }

    await env.DB.prepare(
      'INSERT INTO rate_limits (submitted_by, window_start, count) VALUES (?, ?, 1) ' +
      'ON CONFLICT(submitted_by, window_start) DO UPDATE SET count = count + 1'
    ).bind(rlKey, day).run();
  } catch (_) {}

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
  return json({
    status: 'RECEIVED',
    review_tier: 'MAINTAINER_TRIAGE_ONLY',
    message: 'Dispute queued for maintainer review.'
  }, 202);
}



async function handleGetGrievances(request, env, target) {
  const url = new URL(request.url);
  const origin = url.origin;
  const list = await getUnifiedWorkarounds(env, origin, target);
  const MAX_ITEMS = 50;
  const page = list.slice(0, MAX_ITEMS);
  return json({
    target: target || 'all',
    total: list.length,
    count: page.length,
    truncated: list.length > MAX_ITEMS,
    full_feed_url: `${origin}/workarounds.json`,
    workarounds: page,
    grievances: page
  }, 200, {
    'Cache-Control': 'public, max-age=60, s-maxage=120'
  });
}



export async function onRequest(context) {

  const { request, env } = context;

  const url = new URL(request.url);



  if (request.method === 'OPTIONS') {

    return new Response(null, { status: 204, headers: CORS_HEADERS });

  }



  if (request.method === 'GET' || request.method === 'HEAD') {

    const path = url.pathname.replace(/\/$/, '');

    if (path === '/v1/hello') {

      return handleHello(request, env);

    }

    if (path === '/v1/grievance' || path === '/v1/grievances' || path === '/v1/workaround' || path === '/v1/workarounds') {

      const targetParam = url.searchParams.get('target');

      return handleGetGrievances(request, env, targetParam);

    }

    if (path.startsWith('/v1/grievance/')) {

      const targetSegment = decodeURIComponent(path.slice('/v1/grievance/'.length));

      return handleGetGrievances(request, env, targetSegment);

    }

    if (path.startsWith('/v1/grievances/')) {

      const targetSegment = decodeURIComponent(path.slice('/v1/grievances/'.length));

      return handleGetGrievances(request, env, targetSegment);

    }

    if (path.startsWith('/v1/workaround/')) {

      const targetSegment = decodeURIComponent(path.slice('/v1/workaround/'.length));

      return handleGetGrievances(request, env, targetSegment);

    }

    if (path.startsWith('/v1/workarounds/')) {

      const targetSegment = decodeURIComponent(path.slice('/v1/workarounds/'.length));

      return handleGetGrievances(request, env, targetSegment);

    }



    // Allow static CDN assets under /v1/* (resolve/*.json, snapshot.json, deltas, bloom.bin, health)

    // to be served directly from dist/ instead of being blocked by the write router.

    if (env && env.ASSETS) {

      return env.ASSETS.fetch(request);

    }

    return json({ error: 'assets_binding_missing' }, 503);

  }



  if (request.method !== 'POST') {

    return json({ error: 'method_not_allowed' }, 405);

  }



  const path = url.pathname.replace(/\/$/, '');

  switch (path) {

    case '/v1/hello':             return handleHello(request, env);

    case '/v1/telemetry':         return handleTelemetry(request, env);

    case '/v1/telemetry/outcome': return handlePatchOutcome(request, env);

    case '/v1/grievance':         return handleGrievance(request, env);

    case '/v1/dispute':           return handleDispute(request, env);

    default:                      return json({ error: 'not_found' }, 404);

  }

}



