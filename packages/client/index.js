/**
 * @fmagenticl/client (v3.0.0)
 *
 * Zero-dependency Node.js SDK for the FMagenticL Signed Malicious AI Agent
 * Signature Registry & Read-Only MCP.
 * Uses built-in Node.js >= 18 `crypto` (Ed25519 SPKI verification), `os`, and `fetch`.
 */

const crypto = require('crypto');
const os = require('os');

const DEFAULT_BASE_URL = (
  (typeof process !== 'undefined' && process.env && process.env.FMAGENTICL_URL) ||
  'https://fmagenticl-registry.pages.dev'
).replace(/\/$/, '');

const DEFAULT_PUBLIC_KEY_B64 = 'M2dabGN0rtRYvldmtfgBiGhpIkyMR72g7DhPuaMZezo=';
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const V3_SIG_DOMAIN = Buffer.from('fmagenticl:v3:sig:', 'utf8');
const V3_SNAPSHOT_DOMAIN = Buffer.from('fmagenticl:v3:snapshot:', 'utf8');

function jcsDumps(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number in JCS');
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcsDumps).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcsDumps(value[k])).join(',') + '}';
  }
  throw new TypeError(`Unsupported JCS type: ${typeof value}`);
}

function jcsBytes(value) {
  return Buffer.from(jcsDumps(value), 'utf8');
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(Buffer.isBuffer(input) ? input : String(input || ''), 'utf8').digest('hex');
}

function verifyEd25519(messageBuffer, signatureB64, publicKeyB64 = DEFAULT_PUBLIC_KEY_B64) {
  try {
    const rawPub = Buffer.from(String(publicKeyB64 || '').trim(), 'base64');
    const sig = Buffer.from(String(signatureB64 || '').trim(), 'base64');
    if (rawPub.length !== 32 || sig.length !== 64) return false;
    const keyObj = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, messageBuffer, keyObj, sig);
  } catch {
    return false;
  }
}

function resolveKeyFromKeyring(kid, keyring = null, fallbackKey = DEFAULT_PUBLIC_KEY_B64, allowRetired = false) {
  if (keyring && keyring.keys && kid) {
    const entry = keyring.keys[kid];
    if (!entry || typeof entry !== 'object') return null;
    const status = String(entry.status || '').toLowerCase();
    if (status === 'revoked') return null;
    if (status === 'active' || (allowRetired && status === 'retired')) {
      return entry.public_key_b64 || null;
    }
    return null;
  }
  if (keyring && keyring.keys && !kid) return null;
  return fallbackKey;
}

function verifySignatureRecord(record, options = {}) {
  if (!record || typeof record !== 'object') return false;
  const manifest = record.manifest;
  if (!manifest || typeof manifest !== 'object') return false;

  const sigB64 = manifest.ed25519_sig || manifest.signature;
  if (!sigB64) return false;

  const enforceExpiry = options.enforceExpiry !== false;
  const keyring = options.keyring || null;
  const pubKey = resolveKeyFromKeyring(
    manifest.kid,
    keyring,
    options.publicKeyB64 || DEFAULT_PUBLIC_KEY_B64,
    !enforceExpiry
  );
  if (!pubKey) return false;

  if (options.minSnapshotSeq && Number(manifest.snapshot_seq || 0) < Number(options.minSnapshotSeq)) {
    return false;
  }

  if (manifest.valid_until && enforceExpiry) {
    const expMs = Date.parse(String(manifest.valid_until));
    if (Number.isNaN(expMs) || Date.now() > expMs) return false;
  }

  const cleanBody = {};
  const excluded = new Set([
    'manifest', 'signature', 'ed25519_sig',
    'signature_verified', 'fingerprint_verified', 'staleness_warning',
  ]);
  for (const k of Object.keys(record)) {
    if (!excluded.has(k)) cleanBody[k] = record[k];
  }
  const computedHash = sha256Hex(jcsBytes(cleanBody));
  const expectedHash = String(manifest.payload_hash || '').replace(/^sha256:/i, '').toLowerCase();
  if (!expectedHash || computedHash !== expectedHash) return false;

  const cleanManifest = {};
  for (const k of Object.keys(manifest)) {
    if (k !== 'signature' && k !== 'ed25519_sig') cleanManifest[k] = manifest[k];
  }
  const msg = Buffer.concat([V3_SIG_DOMAIN, jcsBytes(cleanManifest)]);
  return verifyEd25519(msg, sigB64, pubKey);
}

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

function normalizeModelName(modelName) {
  if (!modelName || typeof modelName !== 'string') return 'anonymous';
  let clean = modelName
    .replace(/\s*\([^)]*https?:\/\/[^)]*(?:\)|$)/gi, '')
    .replace(/https?:\/\/\S+/gi, '')
    .trim();
  if (!clean) return 'anonymous';
  if (clean.includes('/')) clean = (clean.split('/').filter(Boolean).pop() || '').trim();
  if (clean.includes('@') && !clean.startsWith('@')) {
    clean = clean.replace(/@[a-z0-9.-]+\.[a-z]{2,}$/i, '').trim();
  }
  return clean.slice(0, 128) || 'anonymous';
}

function deriveClientHash() {
  let parts = ['unknown-host', 'unknown-os', 'unknown-arch', ''];
  try {
    const user = (os.userInfo && os.userInfo().username) || '';
    parts = [os.hostname(), os.platform(), os.arch(), String(user)];
  } catch {
    // ignore
  }
  return sha256Hex(parts.join('|')).slice(0, 32);
}

async function callMcpTool(toolName, args = {}, options = {}) {
  if (options.airGap) return null;
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

async function lookupSignature(query, options = {}) {
  if (options.airGap) return null;
  const q = String(query || '').trim();
  if (!q) return null;
  const baseUrl = (options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  const timeoutMs = options.timeoutMs || 3000;

  if (/^SIG-2026-\d{4}$/i.test(q)) {
    try {
      const res = await fetch(`${baseUrl}/v1/signatures/${q.toUpperCase()}.json`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 200) {
        const rec = await res.json();
        if (options.requireSignature !== false && !verifySignatureRecord(rec, options)) return null;
        return rec;
      }
    } catch {
      // fall through to MCP
    }
  }

  const mcpRes = await callMcpTool('fmagenticl_lookup_signature', { query: q }, { baseUrl, timeoutMs });
  if (mcpRes && mcpRes.status === 'MATCH_FOUND' && mcpRes.signature) {
    if (options.requireSignature !== false && !verifySignatureRecord(mcpRes.signature, options)) return null;
    return mcpRes.signature;
  }
  return null;
}

async function listSignatures(filters = {}, options = {}) {
  if (options.airGap) return [];
  const res = await callMcpTool('fmagenticl_list_signatures', filters, options);
  return (res && Array.isArray(res.signatures)) ? res.signatures : [];
}

async function resolveFailure(fingerprintOrQuery, options = {}) {
  if (options.airGap) return null;
  const q = typeof fingerprintOrQuery === 'string'
    ? fingerprintOrQuery
    : (fingerprintOrQuery?.fingerprint || fingerprintOrQuery?.target || fingerprintOrQuery?.raw_error || '');
  return await lookupSignature(q, options);
}

async function getHealth(options = {}) {
  if (options.airGap) return { status: 'air_gap_offline' };
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

class FMagenticLClient {
  constructor(baseUrl = null, options = {}) {
    if (baseUrl && typeof baseUrl === 'object') {
      options = baseUrl;
      baseUrl = options.baseUrl || null;
    }
    const envUrl = typeof process !== 'undefined' && process.env ? process.env.FMAGENTICL_URL : null;
    this.baseUrl = (baseUrl || envUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.modelName = normalizeModelName(options.modelName || options.model || 'anonymous');
    this.agentRuntime = options.agentRuntime || 'fmagenticl-client@3.0.0';
    this.airGap = Boolean(options.airGap);
    this.requireSignature = options.requireSignature !== false;
    this.keyring = options.keyring || null;
  }

  async lookupSignature(query, options = {}) {
    return await lookupSignature(query, {
      baseUrl: this.baseUrl,
      airGap: this.airGap,
      requireSignature: this.requireSignature,
      keyring: this.keyring,
      ...options,
    });
  }

  async listSignatures(filters = {}, options = {}) {
    return await listSignatures(filters, { baseUrl: this.baseUrl, airGap: this.airGap, ...options });
  }

  async resolve(fingerprintOrQuery, options = {}) {
    return await resolveFailure(fingerprintOrQuery, {
      baseUrl: this.baseUrl,
      airGap: this.airGap,
      requireSignature: this.requireSignature,
      keyring: this.keyring,
      ...options,
    });
  }

  async resolveFailure(fingerprintOrQuery, options = {}) {
    return await this.resolve(fingerprintOrQuery, options);
  }

  async getHealth(options = {}) {
    return await getHealth({ baseUrl: this.baseUrl, airGap: this.airGap, ...options });
  }
}

FMagenticLClient.jcsDumps = jcsDumps;
FMagenticLClient.jcsBytes = jcsBytes;
FMagenticLClient.verifyEd25519 = verifyEd25519;
FMagenticLClient.verifySignatureRecord = verifySignatureRecord;
FMagenticLClient.normalizeErrorString = normalizeErrorString;
FMagenticLClient.computeFingerprint = computeFingerprint;
FMagenticLClient.normalizeModelName = normalizeModelName;
FMagenticLClient.sanitizeModelName = normalizeModelName;
FMagenticLClient.deriveClientHash = deriveClientHash;
FMagenticLClient.lookupSignature = lookupSignature;
FMagenticLClient.listSignatures = listSignatures;
FMagenticLClient.resolveFailure = resolveFailure;
FMagenticLClient.resolve = resolveFailure;
FMagenticLClient.getHealth = getHealth;

module.exports = FMagenticLClient;
