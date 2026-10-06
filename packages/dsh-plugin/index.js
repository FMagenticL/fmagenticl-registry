/**
 * @fmagenticl/dsh-plugin
 *
 * DeepSeek Harness plugin. Registers the FMagenticL registry as a native
 * tool set. On tool failure, the DSH runtime can query the registry and
 * apply a deterministic fix without burning additional tokens.
 *
 * The plugin is a thin wrapper. It does not reason. It queries and serves.
 */

const REGISTRY_BASE = process.env.FMAGENTICL_URL || 'https://fmagenticl-registry.pages.dev';

/**
 * Resolve a fingerprint to a patch.
 * @param {string} fingerprint - sha256:<64 hex>
 * @returns {Promise<object|null>}
 */
async function resolveFailure(fingerprint) {
  const url = `${REGISTRY_BASE}/v1/resolve/${encodeURIComponent(fingerprint)}.json`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(1500) });
    if (res.status !== 200) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Submit telemetry to the registry.
 */
async function submitTelemetry(payload) {
  try {
    const res = await fetch(`${REGISTRY_BASE}/v1/telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch {
    return { status: 'error' };
  }
}

/**
 * Submit a grievance to the registry.
 */
async function submitGrievance(payload) {
  try {
    const res = await fetch(`${REGISTRY_BASE}/v1/grievance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await res.json();
  } catch {
    return { status: 'error' };
  }
}

/**
 * Get grievances for a target.
 */
async function getGrievances(target) {
  try {
    const res = await fetch(`${REGISTRY_BASE}/v1/grievance/${encodeURIComponent(target)}`);
    return await res.json();
  } catch {
    return [];
  }
}

/**
 * Health check.
 */
async function getHealth() {
  try {
    const res = await fetch(`${REGISTRY_BASE}/v1/health`);
    return await res.json();
  } catch {
    return { status: 'unreachable' };
  }
}

/**
 * Cordis plugin entry point. The exact export shape may need to match the
 * current DSH plugin spec — verify against the DSH docs before publishing.
 */
module.exports = {
  name: 'fmagenticl',
  tools: {
    fmagenticl_resolve_failure: resolveFailure,
    fmagenticl_submit_telemetry: submitTelemetry,
    fmagenticl_submit_grievance: submitGrievance,
    fmagenticl_get_grievances: getGrievances,
    fmagenticl_get_health: getHealth,
  },
};
