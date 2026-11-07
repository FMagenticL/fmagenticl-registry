#!/usr/bin/env python3
"""
FMagenticL - Google Drive OAuth Token Re-Authenticator (Scope-Union Safe + Native Chrome Launch)
Refreshes ~/.config/google-drive-mcp/credentials.json while strictly preserving all
pre-existing OAuth scopes (e.g. https://mail.google.com/ + Drive) so sibling MCP servers
never lose authorization.

Usage:
    python scripts/reauth_google_drive.py
"""

import json
import subprocess
import sys
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "google-drive-mcp"
CLIENT_SECRETS = CONFIG_DIR / "client_secrets.json"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"

REQUIRED_DRIVE_SCOPES = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
]


def load_union_scopes() -> list[str]:
    """Preserve every scope already present in credentials.json merged with Drive scopes."""
    existing: set[str] = set()
    if CREDENTIALS_FILE.exists():
        try:
            data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
            for s in data.get("scopes", []):
                if isinstance(s, str) and s.strip():
                    existing.add(s.strip())
        except Exception:
            pass
    return sorted(existing | set(REQUIRED_DRIVE_SCOPES))


def launch_native_chrome(auth_url: str) -> None:
    """Launch Chrome natively on Windows per RULE[windows_direct_browser_execution]."""
    if sys.platform == "win32":
        subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f'Start-Process "chrome.exe" -ArgumentList "{auth_url}"',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def main() -> None:
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "google-auth-oauthlib", "google-api-python-client"]
        )
        from google_auth_oauthlib.flow import InstalledAppFlow

    if not CLIENT_SECRETS.exists():
        print(f"ERROR: client_secrets.json not found at {CLIENT_SECRETS}", file=sys.stderr)
        sys.exit(1)

    scopes = load_union_scopes()
    print(f"Starting OAuth flow with preserved scope union ({len(scopes)} scopes): {scopes}")
    flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRETS), scopes)

    # Bind loopback listener without Python webbrowser fallback; open native Chrome on Windows
    import wsgiref.simple_server
    import urllib.parse

    captured: dict[str, str] = {}

    class _CallbackApp:
        def __call__(self, environ, start_response):
            qs = environ.get("QUERY_STRING", "")
            captured["query"] = qs
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [
                b"<html><body style='font-family:sans-serif;padding:2rem;'>"
                b"<h2>FMagenticL Google Drive + Gmail OAuth Refreshed</h2>"
                b"<p>You may close this tab and return to Antigravity.</p></body></html>"
            ]

    class _QuietHandler(wsgiref.simple_server.WSGIRequestHandler):
        def log_message(self, format, *args):
            pass

    server = wsgiref.simple_server.make_server("127.0.0.1", 0, _CallbackApp(), handler_class=_QuietHandler)
    port = server.server_port
    server.timeout = 110
    flow.redirect_uri = f"http://localhost:{port}/"
    auth_url, _ = flow.authorization_url(access_type="offline", prompt="consent")

    print(f"AUTH_URL: {auth_url}", flush=True)
    launch_native_chrome(auth_url)
    server.handle_request()
    server.server_close()

    if "query" not in captured or "code=" not in captured["query"]:
        print("ERROR: OAuth callback timed out or did not receive authorization code.", file=sys.stderr)
        sys.exit(2)

    params = urllib.parse.parse_qs(captured["query"])
    flow.fetch_token(code=params["code"][0])
    creds = flow.credentials

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.write_text(creds.to_json(), encoding="utf-8")
    print(f"SUCCESS: Fresh OAuth credentials (scopes={list(creds.scopes or scopes)}) written cleanly.")
    print("TIP: In Google Cloud Console -> APIs & Services -> OAuth consent screen, click 'PUBLISH APP' to prevent 7-day Testing TTL expiry.")


if __name__ == "__main__":
    main()
