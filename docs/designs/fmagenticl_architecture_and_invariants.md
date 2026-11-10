# FMagenticL Architecture, Protocol Invariants & Design Specification

**Specification Version**: 1.4.1  
**Status**: APPROVED & LIVING SPECIFICATION  
**Target System**: FMagenticL Registry & MCP Runtime Edge  
**Repository**: `https://github.com/FMagenticL/fmagenticl-registry`  
**Live Edge**: `https://fmagenticl-registry.pages.dev`  

---

## 1. System Intent & Purpose

FMagenticL is a high-availability, distributed Model Context Protocol (MCP) server and static registry designed to provide **zero-latency runtime resilience, patch compilation, and collective herd immunity** for autonomous AI coding agents.

When autonomous agents encounter library deprecations, ecosystem bugs, breaking API changes, or runtime traps (e.g., Pydantic v2 migration errors, LangChain imports, FastMCP socket breaks), FMagenticL provides immediate, pre-verified workarounds and patches without incurring runtime LLM latency, reasoning token costs, or non-deterministic hallucinations.

---

## 2. Core Invariants (Non-Negotiable)

Any implementation drift, bug fix, or automated remediation MUST strictly adhere to these fundamental principles:

### Invariant 1: Zero-LLM Runtime Hot Path
- **Rule**: All runtime responses across `/mcp`, `/v1/health`, `/workarounds.json`, and `/shards/*` must be generated entirely from pre-compiled static JSON, deterministic SQLite/D1 queries, or deterministic Python logic.
- **Prohibition**: Runtime LLM inference in the serving path is strictly prohibited. LLMs may be used for offline triage, code review (EGM), or development assistance, but never in the operational serving loop.

### Invariant 2: Mathematical Conservation & 71-Truth Split
- **Rule**: The system distinguishes between authoritative human-verified workarounds and automated bot-harvested grievances:
  $$\text{Total Grievances} = \text{Verified Workarounds} (71) + \text{Bot-Harvested Grievances} (N)$$
- **Attribution**: Verified workarounds must remain pinned to exactly 71.
- **Cross-Store Parity**: Live D1 database, live CDN endpoints (`/v1/health`, `/workarounds.json`), local `dist/`, and package shards must maintain exact mathematical parity at all times.

### Invariant 3: Ed25519 Cryptographic Verification Honesty
- **Rule**: Patch integrity and provenance verification (`fmagenticl/verify.py`, `fmagenticl/local_cache.py`, `build_distribution.py`) must execute authentic Ed25519 signature checks.
- **Prohibition**: Verification routines must never return synthetic `True` on empty, missing, or malformed signature blocks. Untrusted payloads must be rejected explicitly.

### Invariant 4: Symlink-Safe Dry-Run Hardening
- **Rule**: Patching engines (`fmagenticl/patchers.py`, `fastmcp_server.py`) must verify that target files do not resolve through unauthorized directory symlinks outside the target project/virtual environment.
- **Dry-Run Enforcement**: All patch operations must execute a non-destructive dry-run before altering disk state.

### Invariant 5: RFC 8414 OAuth Discovery Metadata Compliance
- **Rule**: The live edge must serve standard RFC-compliant OAuth authorization server metadata at:
  `/mcp/.well-known/oauth-authorization-server`
  returning HTTP 200 with standard endpoints (`authorization_endpoint`, `token_endpoint`, `response_types_supported`).

### Invariant 6: Fast-404 Edge Shielding & TTFB Guard
- **Rule**: Non-existent or scanner-probed paths (e.g. `/api/query`, `/sw.js`, `/shards/workarounds/fastapi.json`) must return immediate 404 responses from the edge CDN without executing Cloudflare Worker compute.
- **TTFB Ceilings**:
  - `/v1/health`: $\le 3,500\text{ ms}$
  - `/workarounds.json`: $\le 6,500\text{ ms}$
  - `/.well-known/agent-card.json`: $\le 1,000\text{ ms}$
  - Shards (`_recent.json`, `pydantic.json`): $\le 1,200\text{ ms}$

### Invariant 7: Pre-2026 OSV Leak & npm Corruption Isolation
- **Rule**: Grievance databases must contain zero CVE records published prior to 2026 (preventing legacy OSV bloat) and zero npm packages containing `@scope/pkg@[REDACTED` token corruption.

### Invariant 8: Dual Sentry & EGM Autonomous Cadence
- **Sentry v3.1**: Runs every 90 minutes to verify live edge health, TTFB, mathematical parity, GitHub workflows, and Cloudflare analytics.
- **Elephant-Goldfish Model (EGM)**: Runs every 3 Sentry cycles (every 4.5 hours) to detect spec-to-code drift, validate interface readiness, and autonomously remediate detected issues adhering to Core Invariants.

---

## 3. Component Architecture & File Map

| Component | Authoritative File(s) | Primary Function |
|---|---|---|
| Edge Routing & Middleware | `functions/_middleware.js` | Fast-404 shielding, OAuth discovery, caching headers, routing |
| MCP Protocol Server | `fmagenticl/client/fastmcp_server.py`, `server.json` | FastMCP stdio/SSE server offering 6 tools |
| Cryptographic Verification | `fmagenticl/client/verify.py`, `fmagenticl/client/local_cache.py` | Ed25519 signature checks and local shard caching |
| Patch Compilation & Safety | `fmagenticl/client/patchers.py`, `fmagenticl/server/models.py` | Safe dry-run unified diff patching with symlink guards |
| Static Sharding & DB Export | `scripts/export_db_to_static.py`, `scripts/build_distribution.py` | Compiles D1/SQLite into partitioned static shards and dist |
| Sentry Diagnostics Engine | `scripts/run_90min_telemetry.py` | 8-point automated diagnostic suite and adaptive scheduler |
| EGM Cadence & Drift Engine | `scripts/run_egm_cadence.py` | Spec drift audit, Goldfish review, and autonomous remediation |

---

## 4. Verification Protocol

All modifications to this codebase must satisfy:
1. `python -m pytest tests/ -v` passes with 0 failures.
2. `scripts/run_90min_telemetry.py` completes all 8 diagnostic checks with 0 errors.
3. Cryptographic signature and air-gap scanners detect 0 leaks.
4. EGM drift audit detects 0 undocumented divergences between code and this specification.
