# FMagenticL v3.0.0 — Signed Open Registry of Malicious AI Agent Signatures

**FMagenticL** is a standalone, offline-verifiable, Ed25519-signed registry of **malicious AI agent signatures, autonomous offensive harnesses, poisoned MCP servers, and behavioral IOCs** modeled on public advisories (FBI `FLASH-20261113-001`, Treasury `FIN-2026-R002`, CISA KEV, MITRE ATLAS / ATT&CK, and public threat research).

## Confidence Tiers & Categories
- **`CONFIRMED_SIGNATURE`:** Deterministic tool/config/endpoint fingerprints (`OFFENSIVE_AGENT_HARNESS`, `MCP_AND_WORKSPACE_HIJACK`, `EXPLOITED_AI_INFRASTRUCTURE`).
- **`BEHAVIORAL_INDICATOR`:** Machine-speed operational sequences (`AUTONOMOUS_BEHAVIORAL_IOC`).

## Quickstart (Python — Offline-First Default)
```python
from fmagenticl import FMagenticLClient, WorkspaceScanner

client = FMagenticLClient()  # air_gap=True by default (zero outbound network calls)
sig = client.lookup_signature("SIG-2026-0001")
cve = client.lookup_signature("CVE-2025-3248")

# Strictly read-only workspace audit against verified signatures
report = WorkspaceScanner(client).scan_workspace(".")
```

## Quickstart (Node.js — Zero-Dependency Ed25519)
```javascript
const FMagenticLClient = require('@fmagenticl/client');
const client = new FMagenticLClient();
const sig = await client.lookupSignature('SIG-2026-0001');
```

## Read-Only Remote MCP (`https://fmagenticl-registry.pages.dev/mcp`)
- `fmagenticl_lookup_signature(query)`
- `fmagenticl_list_signatures(confidence_tier, threat_category, surface, severity, limit)`
- `fmagenticl_resolve(fingerprint, target, raw_error)`

## Licensing & Non-Affiliation
- Software is MIT licensed (`LICENSE-CODE`); signature catalog data is CC BY 4.0 (`LICENSE-DATA`).
- Independent open-source project; not affiliated with or endorsed by the FBI, CISA, FinCEN, NIST, The MITRE Corporation, OWASP, or any cited research organization. See `NOTICE.md`.
