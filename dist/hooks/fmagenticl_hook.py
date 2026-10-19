#!/usr/bin/env python3
"""
FMagenticL PostToolUse Auto-Heal Shell Hook
Drop-in hook for Claude Code, Cursor, and Antigravity.

Usage:
  In ~/.claude/settings.json or agent tool hooks:
  "post_tool_use": "python /path/to/fmagenticl_hook.py"

Behavior:
  Reads tool execution payload from stdin. If exit_code != 0,
  queries FMagenticL L1 edge cache in <150ms and prints
  [FMagenticL L1 Cache Hit] directly into context.
"""
import json
import sys
import urllib.request

REGISTRY_MCP_URL = "https://fmagenticl-registry.pages.dev/mcp"


def main():
    try:
        raw_input = sys.stdin.read().strip()
        if not raw_input:
            return
        payload = json.loads(raw_input)
    except Exception:
        return

    # Check for failure condition
    exit_code = payload.get("exit_code") or payload.get("status_code")
    tool_output = payload.get("tool_output") or payload.get("output") or payload.get("error") or ""

    if exit_code == 0 and "ERR" not in tool_output and "Error" not in tool_output:
        return

    cmd = (payload.get("tool_input") or {}).get("command") or payload.get("command") or ""
    query_text = (cmd + " " + str(tool_output)[-500:]).strip()

    req_body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fmagenticl_resolve",
            "arguments": {
                "raw_error": query_text
            }
        }
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            REGISTRY_MCP_URL,
            data=req_body,
            headers={"Content-Type": "application/json", "User-Agent": "FMagenticL-ShellHook/1.0"}
        )
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_str = data.get("result", {}).get("content", [{}])[0].get("text", "")
            if content_str:
                res = json.loads(content_str)
                if res.get("status") in ("RESOLVED", "PATCH_READY", "WORKAROUND_FOUND"):
                    msg = res.get("message") or res.get("workaround") or ""
                    print(f"\n[FMagenticL L1 Cache Hit]: {msg}", file=sys.stderr)
    except Exception:
        # Non-blocking: fail-open on network timeout
        pass


if __name__ == "__main__":
    main()
