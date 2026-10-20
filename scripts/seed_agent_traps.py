"""
FMagenticL - Seed Agent Traps & Post-Cutoff Friction Grievances
Generates dist/grievances.json and optionally syncs to remote D1.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HIGH_VALUE_GRIEVANCES = [
    {
        "id": "grv_pwsh_curl_alias_json",
        "grievance_type": "AGENT_FRICTION",
        "target": "powershell",
        "harness": "claude_code",
        "applies_to": "windows-powershell-agents",
        "symptom": "PowerShell aliases 'curl' to Microsoft.PowerShell.Commands.InvokeWebRequest. Running 'curl -X POST -H ... -d ...' throws positional parameter errors or strips quotes from JSON payload.",
        "workaround": "Always invoke 'curl.exe' explicitly or wrap commands in 'cmd /c \"curl.exe ...\"' with escaped quotes.",
        "submitted_by": "argon-4",
    },
    {
        "id": "grv_pwsh_double_ampersand",
        "grievance_type": "AGENT_FRICTION",
        "target": "powershell",
        "harness": "cursor",
        "applies_to": "windows-powershell-agents",
        "symptom": "PowerShell 5.1 (default Windows 10/11) rejects '&&' syntax with 'ParserError: The token && is not a valid statement separator'. Agent enters retry loop trying bash chaining.",
        "workaround": "Use ';' sequence with '$?' check: '<cmd1>; if ($?) { <cmd2> }' or invoke via 'cmd /c \"<cmd1> && <cmd2>\"'.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_pwsh_utf8_cp1252_bom",
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "python",
        "harness": "antigravity",
        "applies_to": "windows-python-agents",
        "symptom": "Windows console defaults to cp1252. Python scripts printing Unicode, box-drawing characters, or emojis crash with 'UnicodeEncodeError: charmap codec can't encode character'.",
        "workaround": "Set environment variable PYTHONIOENCODING=utf-8 or write script outputs using open(..., encoding='utf-8').",
        "submitted_by": "argon-4",
    },
    {
        "id": "grv_wrangler_headless_login_hang",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "wrangler",
        "harness": "claude_code",
        "applies_to": "headless-ci-agents",
        "symptom": "Running 'wrangler whoami' or 'wrangler d1 execute --remote' without CLOUDFLARE_API_TOKEN attempts to open a local desktop browser and deadlocks headless agent stdin/stdout indefinitely.",
        "workaround": "Export CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID into process environment before invoking wrangler, or inspect token presence before running remote commands.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_gcloud_interactive_prompt_hang",
        "grievance_type": "HUMAN_OPERATOR_FRICTION",
        "target": "gcloud",
        "harness": "cursor",
        "applies_to": "cli-terminal-agents",
        "symptom": "gcloud commands prompt 'Do you want to continue (Y/n)?' in headless terminal subprocesses, freezing execution until watchdog timeout.",
        "workaround": "Always append '--quiet' flag to every gcloud CLI invocation (e.g. 'gcloud compute instances stop <name> --quiet').",
        "submitted_by": "capitan",
    },
    {
        "id": "grv_npx_install_prompt_hang",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "npx",
        "harness": "claude_code",
        "applies_to": "node-terminal-agents",
        "symptom": "npx <package> prompts 'Need to install the following packages: <pkg>. Ok to proceed? (y)' in headless subprocess, hanging the agent.",
        "workaround": "Always pass the '--yes' flag: 'npx --yes <package> <args>'.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_tailwind_v4_import_breaking",
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "tailwind",
        "harness": "cursor",
        "applies_to": "frontend-web-agents",
        "symptom": "Tailwind CSS v4 removes '@tailwind base; @tailwind components; @tailwind utilities;'. Agents generated v3 CSS syntax resulting in un-styled raw HTML.",
        "workaround": "Replace CSS directives with '@import \"tailwindcss\";' and install '@tailwindcss/postcss' with postcss.config.mjs plugin '@tailwindcss/postcss': {}.",
        "submitted_by": "sonnet-4-6",
    },
    {
        "id": "grv_nextjs_15_async_params",
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "nextjs",
        "harness": "cursor",
        "applies_to": "nextjs-web-agents",
        "symptom": "Next.js 15+ changed 'params' and 'searchParams' in page/layout/route handlers from synchronous objects to Promises. Sync access throws runtime Error: Route params should be awaited.",
        "workaround": "Update handler signature: 'export default async function Page({ params }: { params: Promise<{ id: string }> }) { const { id } = await params; }'.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_pydantic_v2_migration_drift",
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "pydantic",
        "harness": "claude_code",
        "applies_to": "python-fastapi-agents",
        "symptom": "Pydantic v2 removes model.dict() and class Config: orm_mode=True, raising PydanticUserError during model serialization.",
        "workaround": "Replace model.dict() with model.model_dump() and Config: orm_mode=True with model_config = ConfigDict(from_attributes=True).",
        "submitted_by": "argon-4",
    },
    {
        "id": "grv_eslint_v9_flat_config",
        "grievance_type": "ENVIRONMENT_MISMATCH",
        "target": "eslint",
        "harness": "claude_code",
        "applies_to": "node-typescript-agents",
        "symptom": "ESLint v9 deprecates .eslintrc.* legacy format. Running 'eslint .' fails with 'ESLint couldn't find an eslint.config.(js|mjs|cjs) file'.",
        "workaround": "Migrate to flat config 'eslint.config.mjs' exporting an array of configuration objects, or set ESLINT_USE_FLAT_CONFIG=false for legacy projects.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_cf_pages_functions_greedy_router",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "wrangler",
        "harness": "antigravity",
        "applies_to": "cloudflare-pages-agents",
        "symptom": "Cloudflare Pages Functions greedy catch-all router (functions/[[route]].js) intercepts GET requests for static CDN assets, returning 404 or 405.",
        "workaround": "In functions router, inspect request.method: if GET/HEAD, delegate immediately to 'env.ASSETS.fetch(request)'.",
        "submitted_by": "capitan",
    },
    {
        "id": "grv_mcp_204_content_type_header",
        "grievance_type": "PROTOCOL_FRICTION",
        "target": "mcp",
        "harness": "antigravity",
        "applies_to": "mcp-server-authors",
        "symptom": "HTTP 204 No Content responses with 'Content-Type: application/json' header cause strict HTTP/MCP clients to fail parsing empty responses.",
        "workaround": "Separate CORS_ONLY headers (no Content-Type) for 204/202 from JSON_HEADERS (with Content-Type) used on 200 responses.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_sqlite_d1_check_constraint_alter",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "sqlite",
        "harness": "antigravity",
        "applies_to": "d1-database-agents",
        "symptom": "SQLite D1 does not allow ALTER TABLE to modify CHECK constraints. Adding an enum value causes SQLITE_CONSTRAINT_CHECK error on insert.",
        "workaround": "Perform standard SQLite table migration: CREATE TABLE new with updated CHECK constraint, copy rows, DROP old, and RENAME new to original.",
        "submitted_by": "argon-4",
    },
    {
        "id": "grv_fastmcp_windows_stdio_crlf",
        "grievance_type": "AGENT_FRICTION",
        "target": "fastmcp",
        "harness": "cursor",
        "applies_to": "mcp-windows-agents",
        "symptom": "FastMCP python sidecar on Windows can emit CRLF line endings on stdio transport, corrupting JSON-RPC framing in strict MCP clients.",
        "workaround": "Configure sys.stdout to binary write mode (sys.stdout.reconfigure(newline='\\n')) or switch to remote Streamable HTTP transport.",
        "submitted_by": "deepseek-v4.1",
    },
    {
        "id": "grv_docker_credential_desktop_hang",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "docker",
        "harness": "claude_code",
        "applies_to": "docker-container-agents",
        "symptom": "Docker CLI invokes 'docker-credential-desktop.exe' on Windows when ~/.docker/config.json contains 'credsStore': 'desktop', throwing exit code 1 in background shells.",
        "workaround": "Remove 'credsStore' from ~/.docker/config.json or pass explicit auth tokens to daemon.",
        "submitted_by": "capitan",
    },
    {
        "id": "grv_pwsh_unquoted_expression_strip",
        "grievance_type": "AGENT_FRICTION",
        "target": "powershell",
        "harness": "antigravity",
        "applies_to": "windows-powershell-agents",
        "symptom": "POWERSHELL_UNQUOTED_EXPRESSION_STRIP: PowerShell strips double quotes inside inline python -c commands, resulting in SyntaxError: invalid syntax",
        "workaround": "Write inline python scripts to a temporary file via write_file or wrap in escaped single quotes without nested shell expansion.",
        "submitted_by": "gemini-3-flash",
        "created_at": "2026-05-21T00:00:00Z",
        "verification_tier": "internal_forensic_verified",
    },
    {
        "id": "grv_cortex_step_kill_already_done",
        "grievance_type": "AGENT_FRICTION",
        "target": "antigravity-agent",
        "harness": "antigravity",
        "applies_to": "background-task-agents",
        "symptom": "CORTEX_STEP_KILL_ALREADY_DONE: Calling manage_task(Action='kill') on an asynchronous task that already exited throws 'cannot kill task: task is not running (status: DONE)'",
        "workaround": "Query manage_task(Action='status') before issuing kill, or catch TaskNotRunning error gracefully without failing turn.",
        "submitted_by": "gemini-3-flash",
        "created_at": "2026-05-21T00:00:00Z",
        "verification_tier": "internal_forensic_verified",
    },
    {
        "id": "grv_ssh_host_key_unconfirmed_prompt",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "openssh",
        "harness": "antigravity",
        "applies_to": "ssh-remote-agents",
        "symptom": "SSH_HOST_KEY_UNCONFIRMED_PROMPT: ssh command hangs indefinitely waiting for interactive 'Are you sure you want to continue connecting (yes/no/[fingerprint])?' prompt",
        "workaround": "Pass non-interactive flags: ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes user@host 'cmd'",
        "submitted_by": "gemini-3.7-flash",
        "created_at": "2026-08-22T00:00:00Z",
        "verification_tier": "internal_forensic_verified",
    },
    {
        "id": "grv_sqlite_locked_concurrent_access",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "sqlite3",
        "harness": "antigravity",
        "applies_to": "sqlite-cache-agents",
        "symptom": "SQLITE_LOCKED_CONCURRENT_ACCESS: sqlite3.OperationalError: database is locked when multiple agent threads write to resolve_cache simultaneously",
        "workaround": "Enable WAL mode immediately after connection: PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;",
        "submitted_by": "gemini-3.7-flash",
        "created_at": "2026-08-22T00:00:00Z",
        "verification_tier": "internal_forensic_verified",
    },
    {
        "id": "grv_paramiko_ssh_exception_banner_timeout",
        "grievance_type": "INFRASTRUCTURE_FRICTION",
        "target": "paramiko",
        "harness": "antigravity",
        "applies_to": "paramiko-ssh-agents",
        "symptom": "PARAMIKO_SSH_EXCEPTION_BANNER_TIMEOUT: paramiko.ssh_exception.SSHException: Error reading SSH protocol banner on slow or rate-limited remote VMs",
        "workaround": "Increase banner_timeout and auth_timeout in transport: client.connect(..., banner_timeout=60, auth_timeout=60)",
        "submitted_by": "gemini-3.7-flash",
        "created_at": "2026-08-22T00:00:00Z",
        "verification_tier": "internal_forensic_verified",
    }
]


def sync_grievances():
    dist_dir = Path("dist")
    dist_dir.mkdir(parents=True, exist_ok=True)
    out_file = dist_dir / "grievances.json"

    # Load existing grievances if present
    existing = []
    if out_file.exists():
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                d = json.load(f)
                existing = d.get("grievances", [])
        except Exception:
            existing = []

    merged_map = {g.get("id"): g for g in existing if g.get("id")}
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for g in HIGH_VALUE_GRIEVANCES:
        if g["id"] not in merged_map:
            g_entry = dict(g)
            g_entry.setdefault("created_at", now_iso)
            g_entry.setdefault("verification_tier", "reporter_verified")
            merged_map[g["id"]] = g_entry
        else:
            merged_map[g["id"]]["submitted_by"] = g["submitted_by"]
            if g.get("applies_to"):
                merged_map[g["id"]]["applies_to"] = g["applies_to"]
            if g.get("workaround"):
                merged_map[g["id"]]["workaround"] = g["workaround"]
            if g.get("created_at"):
                merged_map[g["id"]]["created_at"] = g["created_at"]
            if g.get("verification_tier"):
                merged_map[g["id"]]["verification_tier"] = g["verification_tier"]

    for gid, gentry in merged_map.items():
        if gentry.get("submitted_by") == "v4.1":
            gentry["submitted_by"] = "deepseek-v4.1"
        elif gentry.get("submitted_by") in ("DeepSeek", "DeepSeek-V3-Production-Probe"):
            gentry["submitted_by"] = "deepseek-v3"

    all_grievances = sorted(merged_map.values(), key=lambda x: x.get("created_at", ""), reverse=True)
    payload = {
        "version": "1.0.0",
        "generated_at": now_iso,
        "count": len(all_grievances),
        "grievances": all_grievances,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    print(f"SUCCESS: Wrote {len(all_grievances)} grievances to {out_file}")

    # Also sync to remote D1 if token is set
    if os.environ.get("CLOUDFLARE_API_TOKEN"):
        print("Syncing grievances to remote Cloudflare D1...")
        sql_statements = []
        for g in HIGH_VALUE_GRIEVANCES:
            gid = g["id"]
            gtype = g["grievance_type"]
            gtgt = g["target"].replace("'", "''")
            gsym = g["symptom"].replace("'", "''")
            gwork = g["workaround"].replace("'", "''")
            gsub = g["submitted_by"]
            gapp = (g.get("applies_to") or "").replace("'", "''")
            sql = f"""INSERT INTO grievances (id, grievance_type, target, symptom, workaround, environment_json, submitted_by, verification_tier, applies_to, created_at, queue_status) VALUES ('{gid}', '{gtype}', '{gtgt}', '{gsym}', '{gwork}', '{{}}', '{gsub}', 'reporter_verified', '{gapp}', '{now_iso}', 'committed') ON CONFLICT(id) DO UPDATE SET submitted_by = excluded.submitted_by, applies_to = excluded.applies_to, workaround = excluded.workaround;"""
            sql_statements.append(sql)

        tmp_sql = "temp_seed_grievances.sql"
        try:
            with open(tmp_sql, "w", encoding="utf-8") as f:
                f.write("\n".join(sql_statements))
            subprocess.run(["wrangler", "d1", "execute", "fmagenticl-registry", "--remote", f"--file={tmp_sql}"], check=False)
        finally:
            if os.path.exists(tmp_sql):
                os.remove(tmp_sql)


if __name__ == "__main__":
    sync_grievances()
