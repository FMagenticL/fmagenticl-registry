import json
import urllib.request
import urllib.parse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(r"C:\Users\itari\Desktop\Antigravity Projects\Agentic Introspection Agent\fmagenticl")
DAILY_TELEMETRY = REPO_ROOT / "daily_telemetry.md"
CREDS_PATH = Path(r"C:\Users\itari\.config\google-drive-mcp\credentials.json")
FOLDER_ID = "1bXc2DfsVerEoB9sMtI9IM2_crOHRPn4c"  # FMAgenticL Maintenance

def get_access_token():
    if not CREDS_PATH.exists():
        raise FileNotFoundError(f"Credentials not found at {CREDS_PATH}")
    with open(CREDS_PATH, "r", encoding="utf-8") as f:
        creds = json.load(f)
    
    data = urllib.parse.urlencode({
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "refresh_token": creds["refresh_token"],
        "grant_type": "refresh_token"
    }).encode("utf-8")
    
    req = urllib.request.Request(creds.get("token_uri", "https://oauth2.googleapis.com/token"), data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        tokens = json.loads(resp.read().decode("utf-8"))
        return tokens["access_token"]

def find_file_in_folder(token, filename, folder_id):
    query = f"'{folder_id}' in parents and name = '{filename}' and trashed = false"
    url = f"https://www.googleapis.com/drive/v3/files?q={urllib.parse.quote(query)}&fields=files(id,name,webViewLink)"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        files = res.get("files", [])
        return files[0] if files else None

def upload_or_update_telemetry():
    if not DAILY_TELEMETRY.exists():
        print(f"Error: {DAILY_TELEMETRY} not found.")
        return None
    
    with open(DAILY_TELEMETRY, "rb") as f:
        content_bytes = f.read()
    
    token = get_access_token()
    existing = find_file_in_folder(token, "daily_telemetry.md", FOLDER_ID)
    
    if existing:
        file_id = existing["id"]
        # Update existing file content via media upload
        url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media"
        req = urllib.request.Request(url, data=content_bytes, method="PATCH", headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/markdown; charset=UTF-8"
        })
        with urllib.request.urlopen(req) as resp:
            updated = json.loads(resp.read().decode("utf-8"))
            print(f"Successfully updated daily_telemetry.md in Google Drive: ID={file_id}")
            return {
                "id": file_id,
                "name": "daily_telemetry.md",
                "action": "updated",
                "link": existing.get("webViewLink", f"https://drive.google.com/file/d/{file_id}/view")
            }
    else:
        # Create new file via multipart
        boundary = "=======SENTRY_TELEMETRY_BOUNDARY======="
        metadata = {
            "name": "daily_telemetry.md",
            "parents": [FOLDER_ID],
            "mimeType": "text/markdown",
            "description": "FMagenticL Sentry v3.1 90-Minute Autonomous Diagnostic and Telemetry Logs"
        }
        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
            f"{json.dumps(metadata)}\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/markdown; charset=UTF-8\r\n\r\n"
        ).encode("utf-8") + content_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
        
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink"
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/related; boundary={boundary}"
        })
        with urllib.request.urlopen(req) as resp:
            created = json.loads(resp.read().decode("utf-8"))
            print(f"Successfully uploaded daily_telemetry.md to Google Drive: ID={created['id']}")
            return {
                "id": created["id"],
                "name": created.get("name", "daily_telemetry.md"),
                "action": "created",
                "link": created.get("webViewLink", f"https://drive.google.com/file/d/{created['id']}/view")
            }

if __name__ == "__main__":
    result = upload_or_update_telemetry()
    if result:
        print("RESULT:", json.dumps(result))
