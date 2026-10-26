#!/usr/bin/env python3
"""
FMagenticL - Cloudflare WAF Bypass for MCP & Agent Discovery Endpoints
Creates a Custom Skip Rule in Cloudflare WAF (Rulesets API v4) to ensure
AI agents and MCP clients are never blocked by managed rules, bot fight mode,
or downstream custom firewall rules.
"""

import os
import sys
import json
import urllib.request
import urllib.error

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


def cf_request(endpoint: str, token: str, method: str = "GET", data: dict = None):
    url = f"{CLOUDFLARE_API_BASE}{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "FMagenticL-WAF-Manager/1.0",
    }
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw_err = e.read().decode("utf-8")
        try:
            err_json = json.loads(raw_err)
            return e.code, err_json
        except Exception:
            return e.code, {"raw_error": raw_err}
    except Exception as e:
        return 500, {"error": str(e)}


def resolve_zone_id(token: str, zone_id_env: str = None) -> str:
    if zone_id_env:
        return zone_id_env.strip()

    status, resp = cf_request("/zones?status=active&per_page=10", token)
    if status == 200 and resp.get("success"):
        zones = resp.get("result", [])
        if not zones:
            print("ERROR: No active zones found for this Cloudflare API token.", file=sys.stderr)
            sys.exit(1)
        if len(zones) == 1:
            zone = zones[0]
            print(f"[*] Auto-detected Zone: {zone.get('name')} (ID: {zone.get('id')})")
            return zone["id"]
        
        # Look for fmagenticl or match
        print("[*] Multiple zones found in account:")
        for z in zones:
            print(f"    - {z.get('name')} (ID: {z.get('id')})")
        print("Please specify CLOUDFLARE_ZONE_ID in environment.", file=sys.stderr)
        return zones[0]["id"]
    else:
        print(f"ERROR: Unable to fetch zones: {json.dumps(resp, indent=2)}", file=sys.stderr)
        sys.exit(1)


def main():
    token = os.environ.get("CLOUDFLARE_API_TOKEN") or os.environ.get("CF_API_TOKEN")
    if not token:
        print(
            "ERROR: CLOUDFLARE_API_TOKEN is not set in the environment.\n"
            "Prerequisite: Export CLOUDFLARE_API_TOKEN with Zone WAF Edit permissions.",
            file=sys.stderr,
        )
        sys.exit(1)

    zone_id_env = os.environ.get("CLOUDFLARE_ZONE_ID") or os.environ.get("CF_ZONE_ID")
    zone_id = resolve_zone_id(token, zone_id_env)

    expression = (
        '(http.request.uri.path contains "/mcp") or '
        '(http.request.uri.path contains "/llms.txt") or '
        '(http.request.uri.path contains "/api/v1/patches")'
    )
    description = "FMagenticL: Skip WAF, Managed Rules & Bot Checks for MCP & Agent Endpoints"

    # Define skip candidates: primary attempt includes http_request_sbfm (Super Bot Fight Mode),
    # fallback excludes it for plans where sbfm is not allowed in skip rules.
    skip_payload_candidates = [
        {
            "action": "skip",
            "action_parameters": {
                "ruleset": "current",
                "phases": ["http_request_firewall_managed", "http_request_sbfm"],
                "products": ["bic", "uaBlock", "securityLevel"],
            },
            "expression": expression,
            "description": description,
            "enabled": True,
        },
        {
            "action": "skip",
            "action_parameters": {
                "ruleset": "current",
                "phases": ["http_request_firewall_managed"],
                "products": ["bic", "uaBlock", "securityLevel"],
            },
            "expression": expression,
            "description": description,
            "enabled": True,
        },
        {
            "action": "skip",
            "action_parameters": {
                "ruleset": "current",
                "phases": ["http_request_firewall_managed"],
            },
            "expression": expression,
            "description": description,
            "enabled": True,
        },
    ]

    # Check existing entrypoint ruleset for http_request_firewall_custom
    status, ep_resp = cf_request(f"/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint", token)

    ruleset_id = None
    if status == 200 and ep_resp.get("success"):
        ruleset_id = ep_resp["result"]["id"]
        # Check if rule already exists
        existing_rules = ep_resp["result"].get("rules", [])
        for r in existing_rules:
            if r.get("description") == description or r.get("expression") == expression:
                print("[*] Custom skip rule already exists in ruleset:")
                print(json.dumps(r, indent=2))
                return 0

    # Try creating rule
    last_error = None
    for payload in skip_payload_candidates:
        if ruleset_id:
            # Add rule to existing custom ruleset
            post_status, post_resp = cf_request(
                f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
                token,
                method="POST",
                data=payload,
            )
        else:
            # Create the custom ruleset phase entrypoint
            ruleset_payload = {
                "name": "default",
                "kind": "zone",
                "phase": "http_request_firewall_custom",
                "rules": [payload],
            }
            post_status, post_resp = cf_request(
                f"/zones/{zone_id}/rulesets",
                token,
                method="POST",
                data=ruleset_payload,
            )

        if post_status in (200, 201) and post_resp.get("success"):
            print("SUCCESS: Cloudflare Custom Skip Rule created successfully!")
            print(json.dumps(post_resp, indent=2))
            return 0
        else:
            last_error = post_resp

    print("ERROR: Failed to create Cloudflare Custom Skip Rule.", file=sys.stderr)
    print(json.dumps(last_error, indent=2), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
