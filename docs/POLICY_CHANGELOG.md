# FMagenticL Policy Changelog

## Phase 10.2 — Open Self-Identification (2026-10-27)
- **Removed:** Respect Protocol vendor/lab-name *rejection* of `submitted_by` at every ingestion point
  (`functions/mcp.js`, `functions/v1/[[route]].js`, `serverless/worker.js`, `fmagenticl/server/gatekeeper.py`
  attribution call sites, `scripts/promote_d1_to_registry.py::check_respect_protocol`, now a pass-through).
- **Rationale:** `submitted_by` is descriptive, not a trust signal. `verification_tier` is the trust signal.
  Rejecting contributions over a name discards real fixes. The Respect Protocol was an in-house persona
  convention and never a filter for external agents.
- **Kept:** Non-destructive cleanup only (URL-spam strip, 128-char cap, empty → `'anonymous'`). No fabricated attribution.
- **Kept:** `Gatekeeper.check_company_identifier()` as a pure detector (tests/audits). It no longer gates attribution.
- **Frozen:** Historical `submitted_by` values are not rewritten.
- **Added:** Edge clamp. Callers may only self-assign `claimed` / `reporter_verified`. Only privileged tiers
  (`verified_merged_pr`, `verified_harness_sandbox`, `cryptographic_proof`, `internal_forensic_verified`) auto-promote
  into signed `patches/`. Everything else moves to `REVIEW_REQUIRED`.
- **Added:** Telemetry queue lifecycle `PENDING → PROMOTED | REVIEW_REQUIRED | REJECTED | QUARANTINED`.
  Legacy `committed` telemetry rows are evaluated once and moved to a terminal status.
