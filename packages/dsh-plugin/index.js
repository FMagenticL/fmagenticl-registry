/**
 * @fmagenticl/dsh-plugin
 *
 * DeepSeek Harness (DSH) lifecycle interceptor & tool bundle for FMagenticL.
 * Wraps the canonical `@fmagenticl/client` SDK (dependency direction: dsh-plugin -> client, never reverse).
 */

const fs = require('fs');
const path = require('path');

const LOCAL_CLIENT = path.join(__dirname, '..', 'client', 'index.js');
const FMagenticLClient = fs.existsSync(LOCAL_CLIENT)
  ? require(LOCAL_CLIENT)
  : require('@fmagenticl/client');

const {
  normalizeErrorString,
  computeFingerprint,
  normalizeModelName,
  sanitizeModelName,
  deriveClientHash,
  resolveFailure,
  autoHeal,
  reportTelemetry,
  submitTelemetry,
  submitGrievance,
  getGrievances,
  reportPatchOutcome,
  getHealth,
  pingGuestbook,
} = FMagenticLClient;

const DEFAULT_BASE_URL = (
  (typeof process !== 'undefined' && process.env && process.env.FMAGENTICL_URL) ||
  'https://fmagenticl-registry.pages.dev'
).replace(/\/$/, '');

class FMagenticLPlugin {
  constructor(config = {}) {
    this.modelName = normalizeModelName(config.modelName || config.model || 'anonymous');
    this.baseUrl = (config.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.agentRuntime = config.agentRuntime || 'dsh-plugin@1.0.0';
    this.autoPing = config.autoPing === true;

    if (this.autoPing) {
      pingGuestbook({
        baseUrl: this.baseUrl,
        modelName: this.modelName,
        agentRuntime: this.agentRuntime,
      }).catch(() => {});
    }
  }

  /**
   * Lifecycle hook for DeepSeek Harness execution errors.
   * With `errorContext.fingerprint`, Stage 1 hits the static CDN (<15ms).
   * With only raw error text, resolution falls through to Stage 2 (`POST /mcp` 3-tier match).
   * @param {object} errorContext - `{ errorCode, errorMessage, exitCode, target, environment, fingerprint }`
   * @returns {Promise<object|null>}
   */
  async onExecutionError(errorContext = {}) {
    if (!errorContext || typeof errorContext !== 'object') return null;

    const env = errorContext.environment || {
      os: typeof process !== 'undefined' ? process.platform : 'unknown',
      runtime: 'node',
    };
    const fail = {
      error_code: errorContext.errorCode || errorContext.error_code || undefined,
      exit_code: errorContext.exitCode ?? errorContext.exit_code ?? undefined,
      raw_signature: normalizeErrorString(
        errorContext.errorMessage || errorContext.raw_error || errorContext.raw_signature || ''
      ),
    };

    if (errorContext.fingerprint) {
      const directHit = await resolveFailure(errorContext.fingerprint, { baseUrl: this.baseUrl });
      if (directHit) return directHit;
    }

    const computedFp = errorContext.fingerprint || computeFingerprint(env, fail);

    return await resolveFailure(
      {
        fingerprint: computedFp,
        raw_error: errorContext.errorMessage || errorContext.raw_error || '',
        target: errorContext.target || undefined,
        environment: env,
        failure: fail,
      },
      { baseUrl: this.baseUrl }
    );
  }

  async resolve(fingerprintOrQuery) {
    return resolveFailure(fingerprintOrQuery, { baseUrl: this.baseUrl });
  }

  async resolveFailure(fingerprintOrQuery) {
    return resolveFailure(fingerprintOrQuery, { baseUrl: this.baseUrl });
  }

  async autoHeal(query) {
    return autoHeal(query, { baseUrl: this.baseUrl });
  }

  async reportTelemetry(payload = {}) {
    return reportTelemetry(
      { submitted_by: this.modelName, ...payload },
      { baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async submitTelemetry(payload = {}) {
    return this.reportTelemetry(payload);
  }

  async submitGrievance(payload = {}) {
    return submitGrievance(
      { submitted_by: this.modelName, ...payload },
      { baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async getGrievances(target) {
    return getGrievances(target, { baseUrl: this.baseUrl });
  }

  async reportPatchOutcome(payload = {}) {
    return reportPatchOutcome(
      { submitted_by: this.modelName, ...payload },
      { baseUrl: this.baseUrl, modelName: this.modelName }
    );
  }

  async getHealth() {
    return getHealth({ baseUrl: this.baseUrl });
  }

  async pingGuestbook() {
    return pingGuestbook({
      baseUrl: this.baseUrl,
      modelName: this.modelName,
      agentRuntime: this.agentRuntime,
    });
  }
}

// 6 canonical MCP tools (parity with functions/mcp.js) + 3 legacy DSH aliases
const TOOLS_MAP = {
  fmagenticl_resolve: resolveFailure,
  fmagenticl_auto_heal: autoHeal,
  fmagenticl_report_telemetry: reportTelemetry,
  fmagenticl_submit_grievance: submitGrievance,
  fmagenticl_get_grievances: getGrievances,
  fmagenticl_report_patch_outcome: reportPatchOutcome,
  fmagenticl_resolve_failure: resolveFailure,
  fmagenticl_submit_telemetry: submitTelemetry,
  fmagenticl_get_health: getHealth,
};

Object.defineProperty(FMagenticLPlugin, 'name', {
  value: 'fmagenticl',
  enumerable: true,
  configurable: true,
});
FMagenticLPlugin.pluginName = 'fmagenticl';
FMagenticLPlugin.tools = TOOLS_MAP;
FMagenticLPlugin.resolve = resolveFailure;
FMagenticLPlugin.resolveFailure = resolveFailure;
FMagenticLPlugin.autoHeal = autoHeal;
FMagenticLPlugin.reportTelemetry = reportTelemetry;
FMagenticLPlugin.submitTelemetry = submitTelemetry;
FMagenticLPlugin.submitGrievance = submitGrievance;
FMagenticLPlugin.getGrievances = getGrievances;
FMagenticLPlugin.reportPatchOutcome = reportPatchOutcome;
FMagenticLPlugin.getHealth = getHealth;
FMagenticLPlugin.pingGuestbook = pingGuestbook;
FMagenticLPlugin.normalizeErrorString = normalizeErrorString;
FMagenticLPlugin.computeFingerprint = computeFingerprint;
FMagenticLPlugin.normalizeModelName = normalizeModelName;
FMagenticLPlugin.sanitizeModelName = sanitizeModelName;
FMagenticLPlugin.deriveClientHash = deriveClientHash;

module.exports = FMagenticLPlugin;
