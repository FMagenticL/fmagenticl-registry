import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DAILY_TELEMETRY = REPO_ROOT / "daily_telemetry.md"
SCRATCH_DIR = REPO_ROOT / "scratch"
CREDS_PATH = Path.home() / ".config" / "google-drive-mcp" / "credentials.json"
FOLDER_ID = "1bXc2DfsVerEoB9sMtI9IM2_crOHRPn4c"  # FMAgenticL Maintenance
HTTP_TIMEOUT_SEC = 15


def get_access_token() -> str:
    if not CREDS_PATH.exists():
        raise FileNotFoundError(f"Credentials not found at {CREDS_PATH}")
    with open(CREDS_PATH, "r", encoding="utf-8") as f:
        creds = json.load(f)

    data = urllib.parse.urlencode({
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "refresh_token": creds["refresh_token"],
        "grant_type": "refresh_token",
    }).encode("utf-8")

    req = urllib.request.Request(
        creds.get("token_uri", "https://oauth2.googleapis.com/token"),
        data=data,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        tokens = json.loads(resp.read().decode("utf-8"))
        return tokens["access_token"]


def find_file_in_folder(token: str, filename: str, folder_id: str) -> dict | None:
    query = f"'{folder_id}' in parents and name = '{filename}' and trashed = false"
    url = f"https://www.googleapis.com/drive/v3/files?q={urllib.parse.quote(query)}&fields=files(id,name,webViewLink)"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        files = res.get("files", [])
        return files[0] if files else None


def upsert_markdown_file(token: str, filename: str, content_bytes: bytes, description: str) -> dict:
    existing = find_file_in_folder(token, filename, FOLDER_ID)
    if existing:
        file_id = existing["id"]
        url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media"
        req = urllib.request.Request(
            url,
            data=content_bytes,
            method="PATCH",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/markdown; charset=UTF-8",
            },
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
            resp.read()
            print(f"Successfully updated {filename} in Google Drive: ID={file_id}")
            return {
                "id": file_id,
                "name": filename,
                "action": "updated",
                "link": existing.get("webViewLink", f"https://drive.google.com/file/d/{file_id}/view"),
            }

    boundary = "=======SENTRY_TELEMETRY_BOUNDARY======="
    metadata = {
        "name": filename,
        "parents": [FOLDER_ID],
        "mimeType": "text/markdown",
        "description": description,
    }
    body = (
        f"--{boundary}\r\n"
        f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
        f"{json.dumps(metadata)}\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/markdown; charset=UTF-8\r\n\r\n"
    ).encode("utf-8") + content_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/related; boundary={boundary}",
        },
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        created = json.loads(resp.read().decode("utf-8"))
        print(f"Successfully uploaded {filename} to Google Drive: ID={created['id']}")
        return {
            "id": created["id"],
            "name": created.get("name", filename),
            "action": "created",
            "link": created.get("webViewLink", f"https://drive.google.com/file/d/{created['id']}/view"),
        }


def build_escalations_digest_bytes() -> bytes | None:
    if not SCRATCH_DIR.exists():
        return None
    dossiers = sorted(
        list(SCRATCH_DIR.glob("handoff_deepseek_*.md")) + list(SCRATCH_DIR.glob("escalation_argon_*.md")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not dossiers:
        return None
    lines = [
        "# FMagenticL Sentry v3.1 Escalation Dossiers Digest",
        f"- **Synced UTC:** `{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}`",
        f"- **Total Local Dossiers Indexed:** `{len(dossiers)}` (showing latest 10)",
        "",
    ]
    for d in dossiers[:10]:
        lines.append(f"---")
        lines.append(f"## File: `{d.name}`")
        try:
            lines.append(d.read_text(encoding="utf-8").strip())
        except Exception:
            pass
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def upload_or_update_telemetry() -> dict | None:
    if not DAILY_TELEMETRY.exists():
        print(f"Error: {DAILY_TELEMETRY} not found.")
        return None

    content_bytes = DAILY_TELEMETRY.read_bytes()
    token = get_access_token()
    res = upsert_markdown_file(
        token,
        "daily_telemetry.md",
        content_bytes,
        "FMagenticL Sentry v3.1 90-Minute Autonomous Diagnostic and Telemetry Logs",
    )
    digest = build_escalations_digest_bytes()
    if digest:
        esc_res = upsert_markdown_file(
            token,
            "sentry_escalations_digest.md",
            digest,
            "FMagenticL Sentry v3.1 Consolidated Escalation Dossiers Digest",
        )
        res["escalations_digest_id"] = esc_res.get("id")
        res["escalations_digest_link"] = esc_res.get("link")

    # Read and log latest transaction from SWARM_LIVE_LEDGER.jsonl
    try:
        latest_entry = read_latest_swarm_ledger_entry(token)
        if latest_entry:
            res["latest_swarm_entry"] = latest_entry
            print(f"  Swarm Ledger Status: [{latest_entry.get('event')}] node={latest_entry.get('node', latest_entry.get('active_node'))} status={latest_entry.get('status')}")
    except Exception as e:
        print(f"  Swarm Ledger read warning: {e}")

    return res


def read_latest_swarm_ledger_entry(token: str) -> dict | None:
    ledger_folder_id = "1fs6MIksbKuOkVH5rwoiHku6_KtTRnpeS"
    file_info = find_file_in_folder(token, "SWARM_LIVE_LEDGER.jsonl", ledger_folder_id)
    if not file_info:
        return None
    file_id = file_info["id"]
    url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
        content = resp.read().decode("utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if lines:
            return json.loads(lines[-1])
    return None



if __name__ == "__main__":
    result = upload_or_update_telemetry()
    if result:
        print("RESULT:", json.dumps(result))
