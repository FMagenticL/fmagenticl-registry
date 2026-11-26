"""
FMagenticL FastMCP Tooling Sidecar (v3.0.0 — Read-Only Defensive Threat-Signature Registry).
Exposes 3 read-only tools backed by verified local/static signature snapshots:
  1. fmagenticl_lookup_signature
  2. fmagenticl_list_signatures
  3. fmagenticl_resolve (read-only backward-compat alias)
"""

import json
import os
import re
import sys
from typing import Any, Dict, Optional

_pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

try:
    from fastmcp import FastMCP
    mcp = FastMCP("FMagenticL-Threat-Signatures")
    HAS_FASTMCP = True
except ImportError:
    mcp = None
    HAS_FASTMCP = False

from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client.sanitizer import scrub_text

api_base = os.environ.get("FMAGENTICL_API_BASE", "https://fmagenticl-registry.pages.dev")
_client_instance: Optional[FMagenticLClient] = None

_TOKEN_EXTRACT_RE = re.compile(
    r"(SIG-2026-\d{4}|CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|FLASH-\d{8}-\d{3}|FIN-\d{4}-R\d{3}|(?:sha256:)?[0-9a-fA-F]{64})",
    re.IGNORECASE,
)


def _get_client() -> FMagenticLClient:
    global _client_instance
    if _client_instance is None:
        _client_instance = FMagenticLClient(api_base=api_base)
    return _client_instance


class _LazyClientProxy:
    def __getattr__(self, name: str):
        return getattr(_get_client(), name)


client = _LazyClientProxy()


def _lookup_signature(query: str) -> Dict[str, Any]:
    clean_q = scrub_text(str(query or "")).strip()
    if not clean_q:
        return {"status": "NOT_FOUND", "deterministic_miss": True, "message": "Empty query."}
    sig = client.lookup_signature(clean_q)
    if sig:
        return {
            "status": "MATCH_FOUND",
            "signature": sig,
            "references": sig.get("references", []),
        }
    return {
        "status": "NOT_FOUND",
        "deterministic_miss": True,
        "message": "No matching verified threat signature found.",
    }


def _list_signatures(
    confidence_tier: Optional[str] = None,
    threat_category: Optional[str] = None,
    surface: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    items = client.list_signatures(
        confidence_tier=confidence_tier,
        threat_category=threat_category,
        surface=surface,
        severity=severity,
        limit=max(1, min(int(limit or 50), 200)),
    )
    summaries = [
        {
            "id": s.get("id"),
            "confidence_tier": s.get("confidence_tier"),
            "threat_category": s.get("threat_category"),
            "severity": s.get("severity"),
            "title": s.get("title"),
            "surface": (s.get("observable") or {}).get("surface"),
            "references": s.get("references", []),
        }
        for s in items
    ]
    return {"status": "OK", "count": len(summaries), "signatures": summaries}


def _resolve(
    raw_error: Optional[str] = None,
    target: Optional[str] = None,
    fingerprint: Optional[str] = None,
    environment: Optional[Dict[str, str]] = None,
    failure: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    for candidate in (fingerprint, target, raw_error):
        if candidate:
            m = _TOKEN_EXTRACT_RE.search(str(candidate))
            if m:
                sig = client.lookup_signature(m.group(1))
                if sig:
                    return {
                        "status": "RESOLVED",
                        "signature": sig,
                        "patch": sig,
                        "references": sig.get("references", []),
                    }
    return {
        "status": "UNRESOLVED",
        "deterministic_miss": True,
        "cacheable": True,
        "message": "No matching verified threat signature found.",
    }


if HAS_FASTMCP and mcp:
    @mcp.tool()
    def fmagenticl_lookup_signature(query: str) -> str:
        """Exact lookup by SIG-2026-XXXX, CVE, GHSA, advisory ID, or sha256 fingerprint."""
        return json.dumps(_lookup_signature(query=query))

    @mcp.tool()
    def fmagenticl_list_signatures(
        confidence_tier: Optional[str] = None,
        threat_category: Optional[str] = None,
        surface: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> str:
        """List verified threat signatures filtered by tier, category, surface, or severity."""
        return json.dumps(
            _list_signatures(
                confidence_tier=confidence_tier,
                threat_category=threat_category,
                surface=surface,
                severity=severity,
                limit=limit,
            )
        )

    @mcp.tool()
    def fmagenticl_resolve(
        raw_error: Optional[str] = None,
        target: Optional[str] = None,
        fingerprint: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        failure: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Read-only exact resolver by signature ID, CVE/GHSA/advisory token, or sha256."""
        return json.dumps(
            _resolve(
                raw_error=raw_error,
                target=target,
                fingerprint=fingerprint,
                environment=environment,
                failure=failure,
            )
        )


def main():
    if not HAS_FASTMCP or not mcp:
        raise RuntimeError("fastmcp package is required to run fmagenticl-mcp")
    mcp.run()


if __name__ == "__main__":
    main()
