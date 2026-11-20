"""
FMagenticL FastMCP Tooling Sidecar
Allows autonomous agents (Antigravity, Claude Code, Cursor, Windsurf)
to resolve environment failures and trigger deterministic self-healing via standard Model Context Protocol.
"""

import sys
import os
import re
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

from fmagenticl import __version__
from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client.patchers import Patcher
from fmagenticl.client.sanitizer import scrub_structure, scrub_text

api_base = os.environ.get("FMAGENTICL_API_BASE", "https://fmagenticl-registry.pages.dev")
_client_instance: Optional[FMagenticLClient] = None


def _get_client() -> FMagenticLClient:
    """Lazy-initialize FMagenticLClient on first tool invocation (zero network I/O on module import)."""
    global _client_instance
    if _client_instance is None:
        _client_instance = FMagenticLClient(api_base=api_base)
    return _client_instance


class _LazyClientProxy:
    def __getattr__(self, name: str):
        return getattr(_get_client(), name)


client = _LazyClientProxy()


_HEX64_RE = re.compile(r"(?:sha256:)?([0-9a-fA-F]{64})")


def _resolve_patch_lookup(
    environment: Optional[Dict[str, str]] = None,
    failure: Optional[Dict[str, Any]] = None,
    raw_error: Optional[str] = None,
    fingerprint: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Shared deterministic local patch lookup by fingerprint, structured fields, or raw_error."""
    if fingerprint:
        clean_fp = scrub_text(str(fingerprint)).strip()
        hit = client.resolve(clean_fp)
        if hit:
            return hit

    if isinstance(environment, dict) and isinstance(failure, dict) and ((environment or failure) or (not raw_error and not fingerprint)):
        hit = client.resolve_failure(scrub_structure(environment), scrub_structure(failure), context=context)
        if hit:
            return hit

    if raw_error:
        clean_err = scrub_text(str(raw_error))
        m_hex = _HEX64_RE.search(clean_err)
        if m_hex:
            hit = client.resolve(m_hex.group(1).lower())
            if hit:
                return hit
        from fmagenticl.normalizer import canonical_fingerprint
        import hashlib
        cand_norm = canonical_fingerprint(clean_err)
        hit = client.resolve(cand_norm)
        if hit:
            return hit
        cand_raw = hashlib.sha256(clean_err.strip().encode("utf-8")).hexdigest()
        if cand_raw != cand_norm:
            hit = client.resolve(cand_raw)
            if hit:
                return hit

    return None


def _resolve(
    environment: Optional[Dict[str, str]] = None,
    failure: Optional[Dict[str, Any]] = None,
    raw_error: Optional[str] = None,
    target: Optional[str] = None,
    fingerprint: Optional[str] = None,
) -> Dict[str, Any]:
    patch = _resolve_patch_lookup(
        environment=environment,
        failure=failure,
        raw_error=raw_error,
        fingerprint=fingerprint,
    )
    if patch:
        return {"status": "RESOLVED", "patch": patch}
    if target:
        res = client.get_workarounds(scrub_text(str(target)).strip())
        items = res.get("workarounds") or res.get("grievances") or []
        if items:
            return {"status": "WORKAROUND_FOUND", **res}
    return {
        "status": "UNRESOLVED",
        "deterministic_miss": True,
        "cacheable": True,
        "message": "No matching verified patch found in local cache or registry.",
    }


def _auto_heal(
    environment: Optional[Dict[str, str]] = None,
    failure: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    raw_error: Optional[str] = None,
    fingerprint: Optional[str] = None,
) -> Dict[str, Any]:
    ctx = scrub_structure(dict(context or {}))
    # Hard security invariant: MCP _auto_heal ALWAYS executes in read-only dry-run mode
    # (never overridden by caller-supplied context['apply_cli'] or context['dry_run']).
    ctx["dry_run"] = True
    ctx["apply_cli"] = False
    patch = _resolve_patch_lookup(
        environment=environment,
        failure=failure,
        raw_error=raw_error,
        fingerprint=fingerprint,
        context=ctx,
    )
    if patch:
        res_patch = patch.get("remediation") or patch.get("resolution_patch") or patch
        # Validate patch applicability strictly in memory (zero disk mutation, zero shell execution)
        is_applicable = Patcher.apply_patch(res_patch, context=ctx, dry_run=True)
        return {
            "status": "VALIDATED_DRY_RUN" if is_applicable else "VALIDATION_FAILED",
            "action": res_patch.get("action") or res_patch.get("patch_type"),
            "patch_applicable": is_applicable,
            "applied": False,
            "advisory_plan": (
                ctx.get("advisory_cli")
                or res_patch.get("fallback_cli")
                or ctx.get("advisory_workaround")
                or res_patch.get("workaround")
            ),
            "preview_patched_doc": ctx.get("preview_patched_doc"),
            "resolution_patch": res_patch,
            "signature_verified": bool(patch.get("signature_verified", False)),
            "fingerprint_verified": bool(patch.get("fingerprint_verified", False)),
            "notice": "Advisory dry-run validation complete (zero files modified). Inspect resolution patch before applying in a bounded sandbox."
        }
    return {"status": "FAILED", "deterministic_miss": True, "cacheable": True, "message": "Could not auto-heal: No deterministic patch found."}


def _report(
    environment: Dict[str, str],
    failure: Dict[str, Any],
    resolution_patch: Dict[str, Any],
    verified: bool = True,
    technical_note: Optional[str] = None
) -> Dict[str, Any]:
    client.report_failure(
        environment=scrub_structure(environment),
        failure=scrub_structure(failure),
        resolution_patch=scrub_structure(resolution_patch),
        verified=verified,
        technical_note=scrub_structure(technical_note) if technical_note else None
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
        environment=scrub_structure(environment),
        symptom=scrub_structure(symptom),
        workaround=scrub_structure(workaround),
        harness=harness,
        fingerprint=fingerprint,
        submitted_by=submitted_by
    )


def _get_workarounds(target: str) -> Dict[str, Any]:
    return client.get_workarounds(target)


def _get_grievances(target: str) -> Dict[str, Any]:
    return client.get_grievances(target)


def _report_patch_outcome(
    fingerprint: str,
    outcome: str,
    submitted_by: str,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    return client.report_patch_outcome(
        fingerprint=fingerprint,
        outcome=outcome,
        submitted_by=submitted_by,
        notes=scrub_text(notes) if notes else None
    )


if HAS_FASTMCP and mcp:
    @mcp.tool()
    def fmagenticl_resolve(
        raw_error: Optional[str] = None,
        target: Optional[str] = None,
        fingerprint: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Lookup signed patch/workaround by raw_error, target, or sha256 fingerprint. Stateless, idempotent."""
        return json.dumps(_resolve(environment=environment, failure=failure, raw_error=raw_error, target=target, fingerprint=fingerprint))

    @mcp.tool()
    def fmagenticl_auto_heal(
        fingerprint: Optional[str] = None,
        raw_error: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        failure: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Resolve and dry-run validate a patch in memory (no writes or shell)."""
        return json.dumps(_auto_heal(environment=environment, failure=failure, context=context, raw_error=raw_error, fingerprint=fingerprint))

    @mcp.tool()
    def fmagenticl_report_telemetry(
        environment: Dict[str, str],
        failure: Dict[str, Any],
        resolution_patch: Dict[str, Any],
        verified: bool = True,
        technical_note: Optional[str] = None
    ) -> str:
        """Submit verified self-healing patch for quarantine review."""
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
        """Submit friction report with verified workaround."""
        return json.dumps(_submit_grievance(grievance_type, target, environment, symptom, workaround, harness, fingerprint, submitted_by))

    @mcp.tool()
    def fmagenticl_get_workarounds(target: str) -> str:
        """Query verified workarounds for a package or tool."""
        return json.dumps(_get_workarounds(target))

    @mcp.tool()
    def fmagenticl_report_patch_outcome(
        fingerprint: str,
        outcome: str,
        submitted_by: str,
        notes: Optional[str] = None
    ) -> str:
        """Report patch ACK/NACK (3 NACKs quarantine)."""
        return json.dumps(_report_patch_outcome(fingerprint, outcome, submitted_by, notes))


def run_stdio_server():
    """Standard I/O Model Context Protocol (MCP) JSON-RPC 2.0 implementation."""
    TOOLS_LIST = [
        {
            "name": "fmagenticl_resolve",
            "description": "Lookup signed patch/workaround by raw_error, target, or sha256 fingerprint. Stateless, idempotent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "raw_error": {"type": "string"},
                    "target": {"type": "string"},
                    "fingerprint": {"type": "string"},
                    "environment": {"type": "object"},
                    "failure": {"type": "object"}
                }
            }
        },
        {
            "name": "fmagenticl_auto_heal",
            "description": "Resolve and dry-run validate a patch in memory (no writes or shell).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string"},
                    "raw_error": {"type": "string"},
                    "environment": {"type": "object"},
                    "failure": {"type": "object"},
                    "context": {"type": "object"}
                }
            }
        },
        {
            "name": "fmagenticl_report_telemetry",
            "description": "Submit verified self-healing patch for quarantine review.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "environment": {"type": "object"},
                    "failure": {"type": "object"},
                    "resolution_patch": {"type": "object"},
                    "verified": {"type": "boolean"},
                    "technical_note": {"type": "string"},
                    "submitted_by": {"type": "string"}
                },
                "required": ["environment", "failure", "resolution_patch"]
            }
        },
        {
            "name": "fmagenticl_submit_grievance",
            "description": "Submit friction report with verified workaround.",
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
                            "HUMAN_OPERATOR_FRICTION",
                            "AGENT_FRICTION"
                        ]
                    },
                    "target": {"type": "string"},
                    "environment": {"type": "object"},
                    "symptom": {"type": "string"},
                    "workaround": {"type": "string"},
                    "harness": {"type": "string"},
                    "fingerprint": {"type": "string"},
                    "applies_to": {"type": "string"},
                    "submitted_by": {"type": "string"}
                },
                "required": ["grievance_type", "target", "environment", "symptom", "workaround"]
            }
        },
        {
            "name": "fmagenticl_get_workarounds",
            "description": "Query verified workarounds for a package or tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                }
            }
        },
        {
            "name": "fmagenticl_report_patch_outcome",
            "description": "Report patch ACK/NACK (3 NACKs quarantine).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string"},
                    "outcome": {"type": "string", "enum": ["ACK", "NACK"]},
                    "submitted_by": {"type": "string"},
                    "notes": {"type": "string"}
                },
                "required": ["fingerprint", "outcome", "submitted_by"]
            }
        }
    ]
    minimal_profile = os.environ.get("FMAGENTICL_MCP_PROFILE", "").strip().lower() == "minimal"
    advertised_tools = [t for t in TOOLS_LIST if t["name"] in ("fmagenticl_resolve", "fmagenticl_get_workarounds")] if minimal_profile else TOOLS_LIST

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
                        "version": __version__
                    }
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": advertised_tools}
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {}) or {}
                if tool_name == "fmagenticl_resolve":
                    out = _resolve(
                        environment=arguments.get("environment"),
                        failure=arguments.get("failure"),
                        raw_error=arguments.get("raw_error"),
                        target=arguments.get("target"),
                        fingerprint=arguments.get("fingerprint"),
                    )
                elif tool_name == "fmagenticl_auto_heal":
                    out = _auto_heal(
                        environment=arguments.get("environment"),
                        failure=arguments.get("failure"),
                        context=arguments.get("context"),
                        raw_error=arguments.get("raw_error"),
                        fingerprint=arguments.get("fingerprint"),
                    )
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
                elif tool_name in ("fmagenticl_get_workarounds", "fmagenticl_get_grievances"):
                    out = _get_workarounds(arguments.get("target", ""))
                elif tool_name == "fmagenticl_report_patch_outcome":
                    out = _report_patch_outcome(
                        fingerprint=arguments.get("fingerprint", ""),
                        outcome=arguments.get("outcome", "ACK"),
                        submitted_by=arguments.get("submitted_by", "anonymous"),
                        notes=arguments.get("notes")
                    )
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
                result = _resolve(
                    environment=params.get("environment"),
                    failure=params.get("failure"),
                    raw_error=params.get("raw_error"),
                    target=params.get("target"),
                    fingerprint=params.get("fingerprint"),
                )
            elif method == "fmagenticl_auto_heal":
                result = _auto_heal(
                    environment=params.get("environment"),
                    failure=params.get("failure"),
                    context=params.get("context"),
                    raw_error=params.get("raw_error"),
                    fingerprint=params.get("fingerprint"),
                )
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


def main():
    if "--test" in sys.argv:
        env = {"os": "win32", "os_version": "10.0.26100", "runtime": "node@24.15.0", "package": "hermes-agent@0.4.8"}
        fail = {"error_code": "EBADENGINE", "exit_code": 1, "raw_signature": "npm ERR! code EBADENGINE"}
        res = _resolve(env, fail)
        print("MCP_TEST_RESOLVE:", json.dumps(res))
        sys.exit(0)

    if HAS_FASTMCP and mcp:
        mcp.run()
    else:
        run_stdio_server()


if __name__ == "__main__":
    main()
