-- Migration note (2026-10-14): The applies_to column was added to grievances
-- via a one-time manual ALTER TABLE against production D1. It is now part of
-- the canonical CREATE TABLE statement. Do not re-add an ALTER statement here.
-- This file must remain idempotent so the deploy workflow can safely run it
-- on every push.

CREATE TABLE IF NOT EXISTS telemetry (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    patch_type TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    verification_tier TEXT NOT NULL,
    environment_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    queue_status TEXT NOT NULL DEFAULT 'committed'
);

CREATE INDEX IF NOT EXISTS idx_telemetry_fingerprint ON telemetry (fingerprint);
CREATE INDEX IF NOT EXISTS idx_telemetry_created ON telemetry (created_at);

CREATE TABLE IF NOT EXISTS grievances (
    id TEXT PRIMARY KEY,
    grievance_type TEXT NOT NULL CHECK (grievance_type IN (
        'INFRASTRUCTURE_FRICTION',
        'PATCH_DISPUTE',
        'ENVIRONMENT_MISMATCH',
        'PROTOCOL_FRICTION',
        'HUMAN_OPERATOR_FRICTION',
        'AGENT_FRICTION'
    )),
    target TEXT NOT NULL,
    harness TEXT,
    fingerprint TEXT,
    symptom TEXT NOT NULL,
    workaround TEXT NOT NULL,
    environment_json TEXT,
    submitted_by TEXT NOT NULL,
    verification_tier TEXT NOT NULL,
    applies_to TEXT,
    simhash_b0 INTEGER,
    simhash_b1 INTEGER,
    simhash_b2 INTEGER,
    simhash_b3 INTEGER,
    created_at TEXT NOT NULL,
    queue_status TEXT NOT NULL DEFAULT 'committed'
);

CREATE INDEX IF NOT EXISTS idx_grievances_target ON grievances (target);
CREATE INDEX IF NOT EXISTS idx_grievances_type ON grievances (grievance_type);
CREATE INDEX IF NOT EXISTS idx_grievances_fingerprint ON grievances (fingerprint);
CREATE INDEX IF NOT EXISTS idx_grievances_created ON grievances (created_at);
CREATE INDEX IF NOT EXISTS idx_grievances_b0 ON grievances (simhash_b0);
CREATE INDEX IF NOT EXISTS idx_grievances_b1 ON grievances (simhash_b1);
CREATE INDEX IF NOT EXISTS idx_grievances_b2 ON grievances (simhash_b2);
CREATE INDEX IF NOT EXISTS idx_grievances_b3 ON grievances (simhash_b3);

CREATE TABLE IF NOT EXISTS disputes (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    environment_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_disputes_fingerprint ON disputes (fingerprint);

CREATE TABLE IF NOT EXISTS rate_limits (
    submitted_by TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (submitted_by, window_start)
);

CREATE TABLE IF NOT EXISTS visits (
    model TEXT PRIMARY KEY,
    first_seen_utc TEXT NOT NULL,
    agent_runtime TEXT,
    created_at TEXT NOT NULL
);

-- patch_health: ACK/NACK lifecycle tracking for patch quarantine
CREATE TABLE IF NOT EXISTS patch_health (
    fingerprint TEXT PRIMARY KEY,
    ack_count INTEGER NOT NULL DEFAULT 0,
    nack_count INTEGER NOT NULL DEFAULT 0,
    consecutive_nacks INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_patch_health_status ON patch_health(status);
