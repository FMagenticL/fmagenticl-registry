/**
 * @fmagenticl/dsh-plugin
 * DeepSeek Harness (DSH) lifecycle interceptor and collective memory client.
 */

const crypto = require('crypto');

class FMagenticLPlugin {
    constructor(options = {}) {
        const vercelUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null;
        this.serverUrl = options.serverUrl || process.env.FMAGENTICL_URL || vercelUrl || 'https://fmagenticl.vercel.app';
        this.modelName = options.modelName || 'V4';
        this.harness = 'deepseek_harness';
        this.enabled = options.enabled !== false;
    }

    /**
     * Compute SHA-256 fingerprint for a runtime failure.
     */
    computeFingerprint(errorCode, errorMessage, exitCode = null) {
        const payload = JSON.stringify({
            error_code: errorCode,
            exit_code: exitCode,
            signature: (errorMessage || '').slice(0, 512).trim()
        });
        const hex = crypto.createHash('sha256').update(payload).digest('hex');
        return `sha256:${hex}`;
    }

    /**
     * Look up deterministic patch on error intercept.
     */
    async onExecutionError(context) {
        if (!this.enabled) return null;
        try {
            const fp = this.computeFingerprint(
                context.errorCode || context.error?.code || 'UNKNOWN_ERROR',
                context.errorMessage || context.error?.message || '',
                context.exitCode
            );
            const res = await fetch(`${this.serverUrl}/v1/resolve/${encodeURIComponent(fp)}?os=${encodeURIComponent(process.platform)}`);
            if (!res.ok) return null;
            const data = await res.json();
            if (data.status === 'RESOLVED' && data.trust_score >= 0.5) {
                return data;
            }
        } catch (e) {
            // Fail open: never break host agent execution
        }
        return null;
    }

    /**
     * Submit infrastructure friction grievance with actionable workaround.
     */
    async submitGrievance(target, symptom, workaround, grievanceType = 'INFRASTRUCTURE_FRICTION') {
        try {
            const body = {
                grievance_type: grievanceType,
                target: target,
                harness: this.harness,
                environment: {
                    os: process.platform,
                    runtime: `node@${process.version}`
                },
                symptom: symptom,
                workaround: workaround,
                submitted_by: this.modelName
            };
            const res = await fetch(`${this.serverUrl}/v1/grievance`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return await res.json();
        } catch (e) {
            return { status: 'error', detail: e.message };
        }
    }
}

module.exports = FMagenticLPlugin;
