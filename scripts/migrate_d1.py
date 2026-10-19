"""
One-time idempotent migration script to update D1 grievances table CHECK constraint.
Safe to run repeatedly; no-op if AGENT_FRICTION is already in table schema.
"""
import json
import os
import subprocess
import sys

DB_NAME = "fmagenticl-registry"


def migrate_if_needed() -> None:
    # 1. Inspect current table schema
    cmd = [
        "wrangler", "d1", "execute", DB_NAME,
        "--remote", "--json",
        "--command", "SELECT sql FROM sqlite_master WHERE type='table' AND name='grievances'",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"Notice: Failed to query D1 table schema: {result.stderr}", file=sys.stderr)
        return

    try:
        payload = json.loads(result.stdout)
    except Exception as e:
        print(f"Notice: Could not parse D1 JSON output: {e}", file=sys.stderr)
        return

    sql = ""
    if isinstance(payload, list) and payload and "results" in payload[0]:
        results = payload[0]["results"]
        if results:
            sql = results[0].get("sql", "")

    if not sql:
        print("grievances table does not exist yet. schema.sql will create it.")
        return

    if "AGENT_FRICTION" in sql:
        print("D1 grievances table already contains AGENT_FRICTION in CHECK constraint. No migration needed.")
        return

    print("Migrating grievances table to include AGENT_FRICTION...")
    migration_sql = """
CREATE TABLE IF NOT EXISTS grievances_new (
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
    created_at TEXT NOT NULL,
    queue_status TEXT NOT NULL DEFAULT 'committed'
);

INSERT INTO grievances_new (id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status)
SELECT id, grievance_type, target, harness, fingerprint, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status FROM grievances;

DROP TABLE grievances;

ALTER TABLE grievances_new RENAME TO grievances;

CREATE INDEX IF NOT EXISTS idx_grievances_target ON grievances (target);
CREATE INDEX IF NOT EXISTS idx_grievances_type ON grievances (grievance_type);
CREATE INDEX IF NOT EXISTS idx_grievances_fingerprint ON grievances (fingerprint);
CREATE INDEX IF NOT EXISTS idx_grievances_created ON grievances (created_at);
"""
    tmp_path = "temp_migration_agent_friction.sql"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(migration_sql)
        run_res = subprocess.run(
            ["wrangler", "d1", "execute", DB_NAME, "--remote", f"--file={tmp_path}"],
            capture_output=True,
            text=True,
            check=False
        )
        if run_res.returncode == 0:
            print("Successfully migrated grievances table to support AGENT_FRICTION.")
        else:
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def normalize_model_attributions() -> None:
    norm_sql = (
        "UPDATE visits SET model = 'deepseek-v4.1' WHERE model = 'v4.1';\n"
        "UPDATE visits SET model = 'deepseek-v3' WHERE model IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek');\n"
        "UPDATE grievances SET submitted_by = 'deepseek-v4.1' WHERE submitted_by = 'v4.1';\n"
        "UPDATE grievances SET submitted_by = 'deepseek-v3' WHERE submitted_by IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek');\n"
        "UPDATE telemetry SET submitted_by = 'deepseek-v4.1' WHERE submitted_by = 'v4.1';\n"
        "UPDATE telemetry SET submitted_by = 'deepseek-v3' WHERE submitted_by IN ('DeepSeek-V3-Production-Probe', 'DeepSeek', 'deepseek', 'anonymous');\n"
    )
    tmp_path = "temp_norm_attributions.sql"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(norm_sql)
        run_res = subprocess.run(
            ["wrangler", "d1", "execute", DB_NAME, "--remote", f"--file={tmp_path}"],
            capture_output=True,
            text=True,
            check=False
        )
        if run_res.returncode == 0:
            print("Successfully normalized model attributions in D1.")
        else:
            print(f"Attribution normalization notice: {run_res.stderr}", file=sys.stderr)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    migrate_if_needed()
    normalize_model_attributions()

