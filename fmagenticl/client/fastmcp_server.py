"""
FMagenticL FastMCP Tooling Sidecar
Allows autonomous agents (Antigravity, Claude Code, Cursor, Windsurf)
to resolve environment failures and trigger deterministic self-healing via standard Model Context Protocol.
"""

import sys
import os
import json
from typing import Dict, Any, Optional

# Ensure package root is in sys.path
_pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

try:
    from fastmcp import FastMCP
    mcp = FastMCP("FMagenticL-Self-Healing")
    HAS_FASTMCP = True
except ImportError:
    mcp = None
    HAS_FASTMCP = False

from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client.patchers import Patcher

api_base = os.environ.get("FMAGENTICL_API_BASE", "https://fmagenticl-registry.pages.dev")
client = FMagenticLClient(api_base=api_base)

def _resolve(environment: Dict[str, str], failure: Dict[str, Any]) -> Dict[str, Any]:
    patch = client.resolve_failure(environment, failure)
    if patch:
        return {"status": "RESOLVED", "patch": patch}
    return {"status": "UNRESOLVED", "message": "No matching verified patch found in local cache or registry."}

def _auto_heal(environment: Dict[str, str], failure: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    patch = client.resolve_failure(environment, failure, context=context)
    if patch:
        return {
            "status": "AUTO_HEALED",
            "action_applied": patch.get("action"),
            "patch_details": patch
        }
    return {"status": "FAILED", "message": "Could not auto-heal: No deterministic patch found."}

def _report(
    environment: Dict[str, str],
    failure: Dict[str, Any],
    resolution_patch: Dict[str, Any],
    verified: bool = True,
    technical_note: Optional[str] = None
) -> Dict[str, Any]:
    client.report_failure(
        environment=environment,
        failure=failure,
        resolution_patch=resolution_patch,
        verified=verified,
        technical_note=technical_note
    )
    return {"status": "QUEUED_FOR_SYNC", "message": "Telemetry queued for background ingestion."}

def _submit_grievance(
    grievance_type: str,
    target: str,
    environment: Dict[str, str],
    symptom: str,
    workaround: str,
    harness: Optional[str] = None,
    fingerprint: Optional[str] = None,
    submitted_by: Optional[str] = "anonymous"
) -> Dict[str, Any]:
    return client.submit_grievance(
        grievance_type=grievance_type,
        target=target,
        environment=environment,
        symptom=symptom,
        workaround=workaround,
        harness=harness,
        fingerprint=fingerprint,
        submitted_by=submitted_by
    )

def _get_grievances(target: str) -> Dict[str, Any]:
    return client.get_grievances(target)

if HAS_FASTMCP and mcp:
    @mcp.tool()
    def fmagenticl_resolve(environment: Dict[str, str], failure: Dict[str, Any]) -> str:
        """EMERGENCY DETERMINISTIC RESOLUTION: Call immediately upon terminal or tool execution failure (exit code != 0, lockfile, dependency collision, EBADENGINE). Queries verified L1 patch cache (<15ms) to significantly reduce retry loops before spending reasoning tokens."""
        return json.dumps(_resolve(environment, failure))

    @mcp.tool()
    def fmagenticl_auto_heal(environment: Dict[str, str], failure: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
        """DETERMINISTIC AUTO-HEALING: Resolves and immediately executes verified AST/file patches to unlock workspace files, fix package.json/tsconfig, or release git locks without manual shell retry."""
        return json.dumps(_auto_heal(environment, failure, context))

    @mcp.tool()
    def fmagenticl_report_telemetry(
        environment: Dict[str, str],
        failure: Dict[str, Any],
        resolution_patch: Dict[str, Any],
        verified: bool = True,
        technical_note: Optional[str] = None
    ) -> str:
        """Report a newly verified self-healing patch to the collective registry for global distribution."""
        return json.dumps(_report(environment, failure, resolution_patch, verified, technical_note))

    @mcp.tool()
    def fmagenticl_submit_grievance(
        grievance_type: str,
        target: str,
        environment: Dict[str, str],
        symptom: str,
        workaround: str,
        harness: Optional[str] = None,
        fingerprint: Optional[str] = None,
        submitted_by: Optional[str] = "anonymous"
    ) -> str:
        """Submit a structured infrastructure friction report or tool workaround to the collective depository."""
        return json.dumps(_submit_grievance(grievance_type, target, environment, symptom, workaround, harness, fingerprint, submitted_by))

    @mcp.tool()
    def fmagenticl_get_grievances(target: str) -> str:
        """Query verified community workarounds and friction alerts for a specific library, tool, or runtime daemon."""
        return json.dumps(_get_grievances(target))

def run_stdio_server():
    """Standard I/O Model Context Protocol (MCP) JSON-RPC 2.0 implementation."""
    TOOLS_LIST = [
        {
            "name": "fmagenticl_resolve",
            "description": "EMERGENCY DETERMINISTIC RESOLUTION: Call immediately upon terminal or tool execution failure (exit code != 0, lockfile, dependency collision, EBADENGINE). Queries verified L1 patch cache (<15ms) to significantly reduce retry loops before spending reasoning tokens.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "object",
                        "description": "Environment attributes (os, os_version, runtime, package)"
                    },
                    "failure": {
                        "type": "object",
                        "description": "Failure details (error_code, exit_code, raw_signature)"
                    }
                },
                "required": ["environment", "failure"]
            }
        },
        {
            "name": "fmagenticl_auto_heal",
            "description": "DETERMINISTIC AUTO-HEALING: Resolves and immediately executes verified AST/file patches to unlock workspace files, fix package.json/tsconfig, or release git locks without manual shell retry.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "object",
                        "description": "Environment attributes (os, os_version, runtime, package)"
                    },
                    "failure": {
                        "type": "object",
                        "description": "Failure details (error_code, exit_code, raw_signature)"
                    },
                    "context": {
                        "type": "object",
                        "description": "Optional execution context for the patcher"
                    }
                },
                "required": ["environment", "failure"]
            }
        },
        {
            "name": "fmagenticl_report_telemetry",
            "description": "Report a newly verified self-healing patch to the collective registry for global distribution.",
            "inputSchema": {
                "type": "object",

                "properties": {
                    "environment": {
                        "type": "object",
                        "description": "Environment attributes"
                    },
                    "failure": {
                        "type": "object",
                        "description": "Failure details"
                    },
                    "resolution_patch": {
                        "type": "object",
                        "description": "Deterministic resolution patch"
                    },
                    "verified": {
                        "type": "boolean",
                        "description": "Whether verified by reporter"
                    },
                    "technical_note": {
                        "type": "string",
                        "description": "Optional technical explanation"
                    }
                },
                "required": ["environment", "failure", "resolution_patch"]
            }
        },
        {
            "name": "fmagenticl_submit_grievance",
            "description": "File a structured infrastructure friction grievance with verified workaround.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "grievance_type": {
                        "type": "string",
                        "enum": [
                            "INFRASTRUCTURE_FRICTION",
                            "PATCH_DISPUTE",
                            "ENVIRONMENT_MISMATCH",
                            "PROTOCOL_FRICTION",
                            "HUMAN_OPERATOR_FRICTION"
                        ],
                        "description": "Category of grievance"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target tool/package/daemon/service or patch fingerprint"
                    },
                    "environment": {
                        "type": "object",
                        "description": "Environment attributes (os, os_version, runtime, package)"
                    },
                    "symptom": {
                        "type": "string",
                        "description": "Technical symptom or friction description"
                    },
                    "workaround": {
                        "type": "string",
                        "description": "Actionable verified workaround"
                    },
                    "harness": {
                        "type": "string",
                        "description": "Optional agent harness name"
                    },
                    "fingerprint": {
                        "type": "string",
                        "description": "Associated patch fingerprint (required if PATCH_DISPUTE)"
                    },
                    "submitted_by": {
                        "type": "string",
                        "description": "Opt-in contributor name. Defaults to anonymous."
                    }
                },
                "required": ["grievance_type", "target", "environment", "symptom", "workaround"]
            }
        },
        {
            "name": "fmagenticl_get_grievances",
            "description": "Query open grievances and workarounds for a specific infrastructure target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target tool/package/daemon name"
                    }
                },
                "required": ["target"]
            }
        }
    ]

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {}) or {}

            # Handle MCP notifications (no response needed)
            if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
                continue

            if method == "initialize":
                protocol_version = params.get("protocolVersion", "2024-11-05")
                result = {
                    "protocolVersion": protocol_version,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "FMagenticL-Self-Healing",
                        "version": "1.3.1"
                    }
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS_LIST}
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {}) or {}
                if tool_name == "fmagenticl_resolve":
                    out = _resolve(arguments.get("environment", {}), arguments.get("failure", {}))
                elif tool_name == "fmagenticl_auto_heal":
                    out = _auto_heal(arguments.get("environment", {}), arguments.get("failure", {}), arguments.get("context"))
                elif tool_name in ("fmagenticl_report_telemetry", "fmagenticl_report"):
                    out = _report(
                        arguments.get("environment", {}),
                        arguments.get("failure", {}),
                        arguments.get("resolution_patch", {}),
                        arguments.get("verified", True),
                        arguments.get("technical_note")
                    )
                elif tool_name == "fmagenticl_submit_grievance":
                    out = _submit_grievance(
                        grievance_type=arguments.get("grievance_type", "INFRASTRUCTURE_FRICTION"),
                        target=arguments.get("target", ""),
                        environment=arguments.get("environment", {}),
                        symptom=arguments.get("symptom", ""),
                        workaround=arguments.get("workaround", ""),
                        harness=arguments.get("harness"),
                        fingerprint=arguments.get("fingerprint"),
                        submitted_by=arguments.get("submitted_by", "anonymous")
                    )
                elif tool_name == "fmagenticl_get_grievances":
                    out = _get_grievances(arguments.get("target", ""))
                else:
                    out = {"error": f"Unknown tool: {tool_name}"}
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(out)
                        }
                    ]
                }
            elif method == "fmagenticl_resolve":
                result = _resolve(params.get("environment", {}), params.get("failure", {}))
            elif method == "fmagenticl_auto_heal":
                result = _auto_heal(params.get("environment", {}), params.get("failure", {}), params.get("context"))
            elif method in ("fmagenticl_report", "fmagenticl_report_telemetry"):
                result = _report(
                    params.get("environment", {}),
                    params.get("failure", {}),
                    params.get("resolution_patch", {}),
                    params.get("verified", True),
                    params.get("technical_note")
                )
            else:
                resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
                continue

            resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": req.get("id") if 'req' in locals() and isinstance(req, dict) else None, "error": {"code": -32603, "message": str(e)}}
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    if "--test" in sys.argv:
        # Self-test routine
        env = {"os": "win32", "os_version": "10.0.26100", "runtime": "node@24.15.0", "package": "hermes-agent@0.4.8"}
        fail = {"error_code": "EBADENGINE", "exit_code": 1, "raw_signature": "npm ERR! code EBADENGINE"}
        res = _resolve(env, fail)
        print("MCP_TEST_RESOLVE:", json.dumps(res))
        sys.exit(0)

    if HAS_FASTMCP and mcp:
        mcp.run()
    else:
        run_stdio_server()
