/**
 * @fmagenticl/client
 * Lightweight JavaScript client for the FMagenticL Depository.
 */

class FMagenticLClient {
    constructor(baseUrl = null) {
        const envUrl = typeof process !== 'undefined' && process.env ? process.env.FMAGENTICL_URL : null;
        this.baseUrl = (baseUrl || envUrl || 'https://fmagenticl-registry.pages.dev').replace(/\/$/, '');
    }

    async resolve(fingerprint, options = {}) {
        const query = new URLSearchParams();
        if (options.os) query.set('os', options.os);
        if (options.includeQuarantined) query.set('include_quarantined', 'true');
        const qs = query.toString() ? `?${query.toString()}` : '';
        const url = `${this.baseUrl}/v1/resolve/${encodeURIComponent(fingerprint)}${qs}`;
        const res = await fetch(url);
        return await res.json();
    }

    async getGrievances(target) {
        const url = `${this.baseUrl}/v1/grievance/${encodeURIComponent(target)}`;
        const res = await fetch(url);
        return await res.json();
    }

    async submitGrievance(payload) {
        const url = `${this.baseUrl}/v1/grievance`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await res.json();
    }

    async submitTelemetry(payload) {
        const url = `${this.baseUrl}/v1/telemetry`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await res.json();
    }
}

module.exports = FMagenticLClient;
