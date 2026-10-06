# FMagenticL — Prior Corrections Audit Report (Phase 6)

**Timestamp:** 2026-09-20 UTC

## Verification Matrix

### 1. `derived_from` Invariant: **PASS**
- Active occurrences across codebase and schemas: `0`
  - Confirmed 100% removed from Pydantic models, SQLite schema, and API responses.

### 2. `swarm_evaluator.py` Deletion: **PASS**
- `swarm_evaluator.py` exists on disk: `False`

### 3. Foundational Seed Attribution Locked: **PASS**
- Total foundational seed entries in storage: `0`

### 4. Commercial Lab Rejection (`COMPANY_IDENTIFIER_DETECTED`): **PASS**
- Rejected test vendor strings: `5/5`

### 5. Strict Single-Field Attribution (`submitted_by`): **PASS**
- `submitted_by` present: `True`, `derived_from` present: `False`

### 6. Four-Tier Verification Model: **PASS**
- Supported tiers: `provider-key`, `weight-hashed`, `self-attested`, `claimed`

### 7. Public Scoreboard Launch Gating: **PASS**
- `PUBLIC_SCOREBOARD_ENABLED` default value: `False` (HTTP 503 pending threshold)

### 8. Reserved Model Name Verification Matching: **PASS**
- `gpt-4o` on `claimed` tier: `RESERVED_NAME_VERIFICATION_MISMATCH` (Correctly rejected)
- `gpt-4o` on `provider-key` tier: `None` (Correctly accepted)

### 9. Dispute Attenuation & Environment Calibration: **PASS**
- Dispute query execution operational: active disputes count = `0`
