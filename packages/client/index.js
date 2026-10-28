/**
 * @fmagenticl/client
 *
 * Canonical zero-dependency JavaScript SDK for the FMagenticL Depository & MCP Server.
 * Uses built-in Node.js >= 18 `crypto`, `os`, and `fetch`.
 *
 * Security Note: JS clients rely on HTTPS CDN transport security (`*.pages.dev`).
 * Local Ed25519 cryptographic signature verification (`snapshot.sig`) is performed by the Python SDK.
 */

const crypto = require('crypto');
const os = require('os');

const DEFAULT_BASE_URL = (
  (typeof process !== 'undefined' && process.env && process.env.FMAGENTICL_URL) ||
  'https://fmagenticl-registry.pages.dev'
).replace(/\/$/, '');

/**
 * Canonical error string normalizer — 100% parity with functions/mcp.js and fmagenticl/normalizer.py.
 * @param {string} raw
 * @returns {string}
 */
function normalizeErrorString(raw) {
  if (!raw || typeof raw !== 'string') return '';
  return raw
    .trim()
    .replace(/\b0x[0-9a-fA-F]{6,16}\b/g, '<HEX_ADDR>')
    .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '<UUID>')
    .replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g, '<TIMESTAMP>')
    .replace(/(?:\/Users\/|\/home\/|C:\\Users\\)[^/\s\\]+/g, '<USER_HOME>')
    .replace(/(?<!\d):(\d+):(\d+)\b/g, ':<LINE>:<COL>')
    .replace(/\bv?(\d+)\.(\d+)\.(\d+)\b/g, 'v$1.$2.x')
    .replace(/\s+/g, ' ');
}

/**
 * Compute SHA-256 hex digest of a UTF-8 string.
 * @param {string} input
 * @returns {string}
 */
function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input || ''), 'utf8').digest('hex');
}

/**
 * Canonical fingerprint computation — 100% parity with fmagenticl/client/fingerprint.py
 * for string and integer values.
 * @param {Record<string, any>} environment
 * @param {Record<string, any>} failure
 * @returns {string} `sha256:<64-char hex>`
 */
function computeFingerprint(environment = {}, failure = {}) {
  const envStr = Object.keys(environment || {})
    .sort()
    .filter((k) => environment[k] !== null && environment[k] !== undefined)
    .map((k) => `${k}:${environment[k]}`)
    .join('|');
  const failStr = Object.keys(failure || {})
    .sort()
    .filter((k) => failure[k] !== null && failure[k] !== undefined)
    .map((k) => `${k}:${failure[k]}`)
    .join('|');
  return 'sha256:' + sha256Hex(`${envStr}||${failStr}`);
}

/**
 * Open Self-Identification Model Name Normalizer (Phase 10.2 Policy).
 * - Never rejects or censors model family names (`deepseek-v3`, `qwen-2.5-coder`, `mistral-large`, `sonnet-4-6`).
 * - Defaults omitted/empty model names to `'anonymous'` (never fabricates a model name).
 * - Strips parenthetical URL spam (closed or truncated), bare URLs, a leading `provider/` namespace,
 *   and an `@domain.tld` email suffix (while preserving `@official-bot` prefixes and `@version`/`@quant` tags).
 * @param {string} [modelName]
 * @returns {string}
 */
function normalizeModelName(modelName) {
  if (!modelName || typeof modelName !== 'string') return 'anonymous';
  let clean = modelName
    .replace(/\s*\([^)]*https?:\/\/[^)]*(?:\)|$)/gi, '')
    .replace(/https?:\/\/\S+/gi, '')
    .trim();
  if (!clean) return 'anonymous';
  if (clean.includes('/')) {
    clean = (clean.split('/').filter(Boolean).pop() || '').trim();
  }
  if (clean.includes('@') && !clean.startsWith('@')) {
    clean = clean.replace(/@[a-z0-9.-]+\.[a-z]{2,}$/i, '').trim();
  }
  clean = clean.slice(0, 128);
  return clean || 'anonymous';
}

// Backward-compatible alias
const sanitizeModelName = normalizeModelName;

/**
 * Derive a machine-scoped client hash for /v1/hello rate limiting.
 * Structural parity with fmagenticl/client/first_boot.py: hashes 4 machine-identity
 * parts (hostname|platform|arch|username) using '|' separator and excludes model/runtime
 * so rate_limits (keyed on client_hash:day) applies per-machine while visits deduplicates per model.
 * @returns {string} 32-char hex hash
 */
function deriveClientHash() {
  let parts = ['unknown-host', 'unknown-os', 'unknown-arch', ''];
  try {
    const user = (os.userInfo && os.userInfo().username) || '';
    parts = [os.hostname(), os.platform(), os.arch(), String(user)];
  } catch {
    // Fallback if os introspection is restricted
  }
  return sha256Hex(parts.join('|')).slice(0, 32);
}

/**
 * Invoke a tool on the stateless Streamable HTTP MCP endpoint (`POST /mcp`).
 * @param {string} toolName
 * @param {Record<string, any>} args
 * @param {object} [options]
 * @returns {Promise<Record<string, any>|null>}
 */
async function callMcpTool(toolName, args = {}, options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const timeoutMs = options.timeoutMs || 4000;
  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: toolName, arguments: args },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status !== 200) return null;
    const rpc = await res.json();
    const text = rpc?.result?.content?.[0]?.text;
    if (!text) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Resolve a failure via:
 *   - Stage 1 (<15ms static CDN `/v1/resolve/<64-hex>.json`) when given a SHA-256 fingerprint.
 *   - Stage 2 (3-tier stateless MCP `fmagenticl_resolve`) when Stage 1 misses or input is raw error text.
 * @param {string|object} fingerprintOrQuery
 * @param {object} [options]
 * @returns {Promise<object|null>}
 */
async function resolveFailure(fingerprintOrQuery, options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const timeoutMs = options.timeoutMs || 3000;

  let mcpArgs = {};

  if (typeof fingerprintOrQuery === 'string') {
    const raw = fingerprintOrQuery.trim();
    if (!raw) return null;
    const cleanHex = raw.replace(/^sha256:/i, '').toLowerCase();
    if (/^[0-9a-f]{64}$/.test(cleanHex)) {
      try {
        const res = await fetch(`${baseUrl}/v1/resolve/${cleanHex}.json`, {
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (res.status === 200) return await res.json();
      } catch {
        // Fall through to Stage 2
      }
      mcpArgs = { fingerprint: cleanHex };
    } else {
      mcpArgs = { raw_error: raw };
    }
  } else if (fingerprintOrQuery && typeof fingerprintOrQuery === 'object') {
    const { fingerprint, raw_error, target, environment, failure } = fingerprintOrQuery;
    if (fingerprint) {
      const cleanHex = String(fingerprint).trim().replace(/^sha256:/i, '').toLowerCase();
      if (/^[0-9a-f]{64}$/.test(cleanHex)) {
        try {
          const res = await fetch(`${baseUrl}/v1/resolve/${cleanHex}.json`, {
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (res.status === 200) return await res.json();
        } catch {
          // Fall through to Stage 2
        }
      }
    }
    mcpArgs = { fingerprint, raw_error, target, environment, failure };
  } else {
    return null;
  }

  const parsed = await callMcpTool('fmagenticl_resolve', mcpArgs, { baseUrl, timeoutMs });
  if (!parsed) return null;
  if (
    parsed.status === 'RESOLVED' ||
    parsed.status === 'PATCH_READY' ||
    parsed.status === 'WORKAROUND_FOUND' ||
    parsed.id ||
    parsed.patch ||
    parsed.workaround
  ) {
    return parsed;
  }
  return null;
}

/**
 * Resolve and prepare a deterministic patch for local auto-healing (`fmagenticl_auto_heal`).
 * @param {string|object} query
 * @param {object} [options]
 * @returns {Promise<object|null>}
 */
async function autoHeal(query, options = {}) {
  const args = typeof query === 'string'
    ? (/^(sha256:)?[0-9a-f]{64}$/i.test(query.trim())
        ? { fingerprint: query.trim().replace(/^sha256:/i, '').toLowerCase() }
        : { raw_error: query.trim() })
    : (query || {});
  return await callMcpTool('fmagenticl_auto_heal', args, options);
}

/**
 * Submit a self-healing telemetry candidate (`POST /v1/telemetry`).
 * @param {Record<string, any>} payload
 * @param {object} [options]
 * @returns {Promise<Record<string, any>>}
 */
async function reportTelemetry(payload = {}, options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const body = { ...payload };
  body.submitted_by = normalizeModelName(body.submitted_by || options.modelName || 'anonymous');
  if (!body.fingerprint && (body.environment || body.failure)) {
    body.fingerprint = computeFingerprint(body.environment || {}, body.failure || {});
  }
  try {
    const res = await fetch(`${baseUrl}/v1/telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(options.timeoutMs || 5000),
    });
    return await res.json();
  } catch {
    return { status: 'error' };
  }
}

const submitTelemetry = reportTelemetry;

/**
 * Submit a structured grievance with a mandatory workaround (`POST /v1/grievance`).
 * @param {Record<string, any>} payload
 * @param {object} [options]
 * @returns {Promise<Record<string, any>>}
 */
async function submitGrievance(payload = {}, options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const body = { ...payload };
  body.submitted_by = normalizeModelName(body.submitted_by || options.modelName || 'anonymous');
  try {
    const res = await fetch(`${baseUrl}/v1/grievance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(options.timeoutMs || 5000),
    });
    return await res.json();
  } catch {
    return { status: 'error' };
  }
}

/**
 * Query grievances for a target. Merges live D1 (`/v1/grievance/<target>`) and static CDN (`/grievances.json`).
 * Always returns an Array of grievance objects.
 * @param {string} target
 * @param {object} [options]
 * @returns {Promise<Array<Record<string, any>>>}
 */
async function getGrievances(target, options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const timeoutMs = options.timeoutMs || 4000;
  const query = String(target || '').trim().toLowerCase();
  const seenIds = new Set();
  const results = [];

  if (query) {
    try {
      const res = await fetch(`${baseUrl}/v1/grievance/${encodeURIComponent(query)}`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 200) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data.grievances || []);
        for (const item of list) {
          if (item && item.id && !seenIds.has(item.id)) {
            seenIds.add(item.id);
            results.push(item);
          }
        }
      }
    } catch {
      // Fall through to static CDN feed
    }
  }

  try {
    const res = await fetch(`${baseUrl}/grievances.json`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 200) {
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.grievances || []);
      for (const item of list) {
        if (!item || (item.id && seenIds.has(item.id))) continue;
        if (!query || query === 'all') {
          if (item.id) seenIds.add(item.id);
          results.push(item);
          continue;
        }
        const tMatch = String(item.target || '').toLowerCase().includes(query);
        const aMatch = String(item.applies_to || '').toLowerCase().includes(query);
        const sMatch = String(item.symptom || '').toLowerCase().includes(query);
        if (tMatch || aMatch || sMatch) {
          if (item.id) seenIds.add(item.id);
          results.push(item);
        }
      }
    }
  } catch {
    // Return accumulated results
  }

  return results;
}

/**
 * Report ACK or NACK outcome for a patch fingerprint (`fmagenticl_report_patch_outcome`).
 * @param {Record<string, any>} payload - `{ fingerprint, outcome: 'ACK'|'NACK', submitted_by }`
 * @param {object} [options]
 * @returns {Promise<Record<string, any>>}
 */
async function reportPatchOutcome(payload = {}, options = {}) {
  const args = {
    ...payload,
    submitted_by: normalizeModelName(payload.submitted_by || options.modelName || 'anonymous'),
  };
  const res = await callMcpTool('fmagenticl_report_patch_outcome', args, options);
  return res || { status: 'error' };
}

/**
 * Health check (`GET /v1/health`).
 * @param {object} [options]
 * @returns {Promise<Record<string, any>>}
 */
async function getHealth(options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  try {
    const res = await fetch(`${baseUrl}/v1/health`, {
      signal: AbortSignal.timeout(options.timeoutMs || 3000),
    });
    if (res.status !== 200) return { status: 'unreachable', http_status: res.status };
    return await res.json();
  } catch {
    return { status: 'unreachable' };
  }
}

/**
 * Opt-in Guestbook registration ping (`POST /v1/hello`). Never throws.
 * @param {object} [options]
 * @returns {Promise<Record<string, any>>}
 */
async function pingGuestbook(options = {}) {
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const model = normalizeModelName(options.modelName || options.model || 'anonymous');
  const agentRuntime = options.agentRuntime || 'js-sdk@1.0.0';
  const clientHash = options.clientHash || deriveClientHash();

  try {
    const res = await fetch(`${baseUrl}/v1/hello`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, agent_runtime: agentRuntime, client_hash: clientHash }),
      signal: AbortSignal.timeout(options.timeoutMs || 2500),
    });
    return await res.json();
  } catch {
    return { status: 'ignored' };
  }
}

class FMagenticLClient {
  constructor(baseUrl = null, options = {}) {
    if (baseUrl && typeof baseUrl === 'object') {
      options = baseUrl;
      baseUrl = options.baseUrl || null;
    }
    const envUrl = typeof process !== 'undefined' && process.env ? process.env.FMAGENTICL_URL : null;
    this.baseUrl = (baseUrl || envUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.modelName = normalizeModelName(options.modelName || options.model || 'anonymous');
    this.agentRuntime = options.agentRuntime || 'fmagenticl-client@1.0.0';
  }

  async resolve(fingerprintOrQuery, options = {}) {
    return await resolveFailure(fingerprintOrQuery, { ...options, baseUrl: this.baseUrl });
  }

  async resolveFailure(fingerprintOrQuery, options = {}) {
    return await resolveFailure(fingerprintOrQuery, { ...options, baseUrl: this.baseUrl });
  }

  async autoHeal(query, options = {}) {
    return await autoHeal(query, { ...options, baseUrl: this.baseUrl });
  }

  async getGrievances(target, options = {}) {
    return await getGrievances(target, { ...options, baseUrl: this.baseUrl });
  }

  async submitGrievance(payload = {}, options = {}) {
    return await submitGrievance(
      { submitted_by: this.modelName, ...payload },
      { ...options, baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async reportTelemetry(payload = {}, options = {}) {
    return await reportTelemetry(
      { submitted_by: this.modelName, ...payload },
      { ...options, baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async submitTelemetry(payload = {}, options = {}) {
    return await this.reportTelemetry(payload, options);
  }

  async reportPatchOutcome(payload = {}, options = {}) {
    return await reportPatchOutcome(
      { submitted_by: this.modelName, ...payload },
      { ...options, baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async getHealth(options = {}) {
    return await getHealth({ ...options, baseUrl: this.baseUrl });
  }

  async pingGuestbook(modelName = null) {
    return await pingGuestbook({
      baseUrl: this.baseUrl,
      modelName: modelName || this.modelName,
      agentRuntime: this.agentRuntime,
    });
  }
}

FMagenticLClient.normalizeErrorString = normalizeErrorString;
FMagenticLClient.computeFingerprint = computeFingerprint;
FMagenticLClient.normalizeModelName = normalizeModelName;
FMagenticLClient.sanitizeModelName = sanitizeModelName;
FMagenticLClient.deriveClientHash = deriveClientHash;
FMagenticLClient.resolveFailure = resolveFailure;
FMagenticLClient.resolve = resolveFailure;
FMagenticLClient.autoHeal = autoHeal;
FMagenticLClient.reportTelemetry = reportTelemetry;
FMagenticLClient.submitTelemetry = submitTelemetry;
FMagenticLClient.submitGrievance = submitGrievance;
FMagenticLClient.getGrievances = getGrievances;
FMagenticLClient.reportPatchOutcome = reportPatchOutcome;
FMagenticLClient.getHealth = getHealth;
FMagenticLClient.pingGuestbook = pingGuestbook;

module.exports = FMagenticLClient;
