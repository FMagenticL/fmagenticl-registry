"""
Middleware client for the FMagenticL client SDK.

Resolves a fingerprint through three tiers:
    1. Local cache (memory snapshot + on-disk delta cache).
    2. Edge CDN fetch (single-attempt, bounded timeout, circuit-breaker gated,
       with cryptographic signature & fingerprint verification).
    3. Graceful bypass (return None, never raise, never block the host) -- except under air-gap,
   where an unverifiable snapshot is refused loudly rather than silently egressed.

Contract with the host agent runtime:
    - resolve() returns a patch dict or None. It never raises -- EXCEPT in air-gap mode, where
      unverifiable local data raises FMagenticLIntegrityError instead of silently egressing (F2).
      The report_*/get_* methods preserve their "never raises" contract: they return a
      REFUSED_AIR_GAP status dict instead of reaching the network.
    - Worst-case latency is bounded by the HTTP timeout (1.5s total).
    - A missing patch is a signal, not an error.

Also exports (preserved from prior interface):
    - CircuitBreaker: three-state resilience primitive.
    - parse_retry_after: HTTP Retry-After header parser.
    - MiddlewareClient: alias for FMagenticLClient.
    - FMagenticLClient.compute_fingerprint: deterministic fingerprint from
      environment and failure dicts.
"""

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import httpx

from .config import EDGE_BASE, TIMEOUT
from .local_cache import LocalCache
from .fingerprint import (
    compute_fingerprint as _compute_fingerprint,
    compute_normalized_fingerprint as _compute_normalized_fingerprint,
)
from .sanitizer import scrub_structure, scrub_text
from .verify import verify_patch_signature, verify_patch_fingerprint, verify_patch_envelope
from .errors import FMagenticLIntegrityError


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Three-state circuit breaker: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.

    CLOSED:     Requests pass through. Failures accumulate.
    OPEN:       Requests are rejected until reset_timeout elapses.
    HALF_OPEN:  A single probe request is allowed. On success, closes.
                On failure, reopens and the timer resets.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 3, reset_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = self.CLOSED

    def can_request(self) -> bool:
        if self.state == self.CLOSED:
            return True
        if self.state == self.OPEN:
            if time.time() - self.last_failure_time > self.reset_timeout:
                self.state = self.HALF_OPEN
                return True
            return False
        return True  # HALF_OPEN: allow one probe.

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = self.CLOSED

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = self.OPEN


# ---------------------------------------------------------------------------
# Retry-After parser (HTTP 429 / 503 backoff)
# ---------------------------------------------------------------------------

def parse_retry_after(header_value: Optional[str], default_fallback: float = 5.0) -> Optional[float]:
    """
    Parses a Retry-After header value into a seconds-from-now float.
    Handles integer seconds and RFC 7231 HTTP-date formats.
    Returns default_fallback (5.0s) if missing or unparseable.
    """
    if not header_value:
        return default_fallback
    val = header_value.strip()
    try:
        return max(0.0, float(val))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(val)
        now = datetime.now(timezone.utc)
        return max(0.0, (dt - now).total_seconds())
    except Exception:
        return default_fallback


# ---------------------------------------------------------------------------
# FMagenticLClient
# ---------------------------------------------------------------------------

class FMagenticLClient:
    """
    Primary client for the FMagenticL registry.

    Resolves fingerprints through the local cache first, then the edge
    CDN, gated by a circuit breaker to prevent hammering an unhealthy
    endpoint.
    """

    def __init__(
        self,
        local_cache: Optional[LocalCache] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        edge_base: Optional[str] = None,
        api_base: Optional[str] = None,
        local_cache_path: Optional[str] = None,
        circuit_failure_threshold: Optional[int] = None,
        circuit_reset_timeout: Optional[float] = None,
        timeout: Optional[float] = None,
        model_name: str = "unknown",
        agent_runtime: Optional[str] = None,
        require_signature: bool = True,
        air_gap: Optional[bool] = None,
        **kwargs,
    ):
        if local_cache is not None:
            self.local_cache = local_cache
        else:
            self.local_cache = LocalCache(delta_path=local_cache_path) if local_cache_path else LocalCache()

        if circuit_breaker is not None:
            self.circuit_breaker = circuit_breaker
        elif circuit_failure_threshold or circuit_reset_timeout:
            self.circuit_breaker = CircuitBreaker(
                failure_threshold=circuit_failure_threshold or 3,
                reset_timeout=circuit_reset_timeout or 30.0,
            )
        else:
            self.circuit_breaker = CircuitBreaker()

        self.edge_base = edge_base or api_base or EDGE_BASE
        self.timeout = timeout
        self.model_name = model_name
        self.agent_runtime = agent_runtime
        self.require_signature = (
            require_signature
            if os.environ.get("FMAGENTICL_REQUIRE_SIGNATURE", "1").lower() not in ("false", "0")
            else False
        )
        # F2 (2026-11-25): air-gap mode defaults ON - fail closed rather than silently egress.
        if air_gap is None:
            air_gap = os.environ.get("FMAGENTICL_AIR_GAP", "1").lower() not in ("false", "0")
        self.air_gap = bool(air_gap)
        self._metrics = {
            "memory_hit": 0,
            "delta_hit": 0,
            "edge_hit": 0,
            "edge_miss": 0,
            "edge_timeout": 0,
            "edge_parse_error": 0,
            "breaker_open": 0,
            "bypass": 0,
            "integrity_refusal": 0,
        }

        # auto_ping is deprecated and ignored (zero outbound pings on client init)
        _ = kwargs.get("auto_ping", False)

    # -----------------------------------------------------------------------
    # Fingerprint computation (static, called at import time by seed modules)
    # -----------------------------------------------------------------------

    @staticmethod
    def compute_fingerprint(environment: dict, failure: dict) -> str:
        """
        Deterministic SHA-256 fingerprint from environment and failure dicts.

        Canonical form:
            sha256:<64 hex chars>
        """
        return _compute_fingerprint(environment, failure)

    # -----------------------------------------------------------------------
    # Resolution
    # -----------------------------------------------------------------------

    def _resolve_tier1(self, fp_hex: str) -> Optional[dict]:
        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        if hasattr(self.local_cache, "get_with_source"):
            cached, from_memory, canonical_hex = self.local_cache.get_with_source(clean_hex)
        else:
            cached = self.local_cache.get(clean_hex) or self.local_cache.get(fp_hex)
            from_memory = False
            canonical_hex = clean_hex
            if cached is not None and hasattr(self.local_cache, "_lock") and hasattr(self.local_cache, "_memory"):
                with self.local_cache._lock:
                    if clean_hex in self.local_cache._memory or fp_hex in self.local_cache._memory:
                        from_memory = True
        if cached is None:
            return None

        if from_memory:
            self._metrics["memory_hit"] += 1
        else:
            self._metrics["delta_hit"] += 1

        if isinstance(cached, dict):
            snap_verified = bool(getattr(self.local_cache, "_snapshot_signature_verified", False))
            pub_key = getattr(self.local_cache, "public_key_b64", None)
            if "manifest" in cached:
                sig_ok = verify_patch_envelope(
                    cached,
                    expected_fingerprint=canonical_hex,
                    public_key_b64=pub_key,
                    enforce_expiry=True,
                )
                if not sig_ok and from_memory and snap_verified:
                    sig_ok = verify_patch_envelope(
                        cached,
                        expected_fingerprint=canonical_hex,
                        public_key_b64=pub_key,
                        enforce_expiry=False,
                    )
                    if sig_ok:
                        cached["staleness_warning"] = True
            else:
                sig_ok = (from_memory and snap_verified) or verify_patch_signature(cached, public_key_b64=pub_key)
            if self.require_signature and not sig_ok:
                return None
            cached["signature_verified"] = sig_ok
            cached["fingerprint_verified"] = verify_patch_fingerprint(cached, expected_fp=canonical_hex)
        return cached

    def _resolve_tier2(self, fp_hex: str) -> Optional[dict]:
        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        if not self.circuit_breaker.can_request():
            self._metrics["breaker_open"] += 1
            self._metrics["bypass"] += 1
            return None

        patch = self._query_remote(clean_hex)
        if patch is not None:
            self.circuit_breaker.record_success()
            self.local_cache.put(clean_hex, patch)
            return patch
        return None

    def resolve(self, fp_hex: str) -> Optional[dict]:
        tier1 = self._resolve_tier1(fp_hex)
        if tier1 is not None:
            return tier1

        if self.air_gap:
            self._assert_egress_allowed("network fallback")
            self._metrics["bypass"] += 1
            return None

        clean_hex = fp_hex.replace("sha256:", "").strip().lower()
        if not self.circuit_breaker.can_request():
            self._metrics["breaker_open"] += 1
            self._metrics["bypass"] += 1
            return None

        patch = self._query_remote(clean_hex)
        if patch is not None:
            self.circuit_breaker.record_success()
            self.local_cache.put(clean_hex, patch)
            return patch

        self._metrics["bypass"] += 1
        return None

    def lookup_signature(self, query: str) -> Optional[dict]:
        """Exact deterministic lookup by SIG-2026-XXXX, sha256:<hex>, CVE, GHSA, or advisory ID."""
        if not query or not isinstance(query, str):
            return None
        q_clean = query.strip()
        if not q_clean:
            return None

        # Tier 1: Direct SHA-256 hex or local cache alias lookup
        q_lower = q_clean.lower()
        alias_hex = self.local_cache.resolve_alias(q_lower)
        if alias_hex != q_lower:
            res = self.resolve(alias_hex)
            if res is not None:
                return res

        # If query is already a 64-char sha256 hex (with or without prefix), resolve directly
        clean_hex = q_lower.replace("sha256:", "").strip()
        if len(clean_hex) == 64 and all(c in "0123456789abcdef" for c in clean_hex):
            return self.resolve(clean_hex)

        # If query is a SIG-YYYY-NNNN ID: check integrity gate, then Tier-2 edge fallback if air_gap=False
        if re.match(r"^SIG-\d{4}-\d{4,}$", q_clean, re.IGNORECASE):
            sig_upper = q_clean.upper()
            local_rec = self.local_cache.get_by_id(sig_upper) if hasattr(self.local_cache, "get_by_id") else None
            if local_rec is not None:
                return local_rec
            self._assert_egress_allowed("signature lookup")
            if self.air_gap:
                self._metrics["bypass"] += 1
                return None
            fp_hex = hashlib.sha256(sig_upper.encode("utf-8")).hexdigest()
            res = self.resolve(fp_hex)
            if res is not None:
                return res
            return self._query_remote_signature_id(sig_upper)

        return None

    def _query_remote_signature_id(self, sig_id: str) -> Optional[dict]:
        """Tier-2 fallback to GET /v1/signatures/{sig_id}.json when air_gap=False."""
        self._assert_egress_allowed("signature lookup")
        if self.air_gap or not self.circuit_breaker.can_request():
            return None
        url = f"{self.edge_base.rstrip('/')}/v1/signatures/{sig_id}.json"
        try:
            req_timeout = self.timeout or TIMEOUT
            response = httpx.get(url, timeout=req_timeout, follow_redirects=False)
        except (httpx.TimeoutException, httpx.RequestError):
            self._metrics["edge_timeout"] += 1
            self.circuit_breaker.record_failure()
            return None
        if response.status_code != 200:
            self._metrics["edge_miss"] += 1
            if response.status_code >= 500:
                self.circuit_breaker.record_failure()
            return None
        try:
            patch = response.json()
        except (ValueError, json.JSONDecodeError):
            self._metrics["edge_parse_error"] += 1
            return None
        if not isinstance(patch, dict):
            return None
        fp_hex = hashlib.sha256(sig_id.encode("utf-8")).hexdigest()
        pub_key = getattr(self.local_cache, "public_key_b64", None) if hasattr(self, "local_cache") else None
        if "manifest" in patch:
            sig_ok = verify_patch_envelope(patch, expected_fingerprint=fp_hex, public_key_b64=pub_key)
            if not sig_ok:
                self._metrics["signature_invalid"] += 1
                return None
            self.circuit_breaker.record_success()
            self.local_cache.put(fp_hex, patch)
            return patch
        if self.require_signature:
            self._metrics["signature_invalid"] += 1
            return None
        self.circuit_breaker.record_success()
        self.local_cache.put(fp_hex, patch)
        return patch

    def list_signatures(
        self,
        confidence_tier: Optional[str] = None,
        threat_category: Optional[str] = None,
        surface: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Filter verified in-memory threat signatures deterministically."""
        if self.air_gap and getattr(self.local_cache, "_snapshot_verification_failed", False):
            self._assert_egress_allowed("signature listing")
        items = self.local_cache.list_all() if hasattr(self.local_cache, "list_all") else []
        out = []
        for item in items:
            if confidence_tier and item.get("confidence_tier") != confidence_tier:
                continue
            if threat_category and item.get("threat_category") != threat_category:
                continue
            if severity and item.get("severity") != severity:
                continue
            if surface and (item.get("observable") or {}).get("surface") != surface:
                continue
            out.append(item)
            if len(out) >= limit:
                break
        return out

    def scan_workspace(self, root_path: str) -> dict:
        """Run strictly read-only WorkspaceScanner against verified local signatures."""
        from fmagenticl.client.scanner import WorkspaceScanner
        return WorkspaceScanner(self).scan_workspace(root_path)

    def resolve_failure(
        self,
        environment: dict,
        failure: dict,
        context: Optional[dict] = None
    ) -> Optional[dict]:
        """Attempt to resolve a failure via 3 tiers (offline L1 raw+norm before remote breaker)."""
        fp_raw = self.compute_fingerprint(environment, failure)
        fp_norm = _compute_normalized_fingerprint(environment, failure)

        # Tier 1 probes always execute regardless of remote circuit-breaker state
        for fp in ([fp_raw, fp_norm] if fp_norm != fp_raw else [fp_raw]):
            hit = self._resolve_tier1(fp)
            if hit is not None:
                return hit

        if self.air_gap:
            self._assert_egress_allowed("network fallback")
            self._metrics["bypass"] += 1
            return None

        if not self.circuit_breaker.can_request():
            self._metrics["breaker_open"] += 1
            self._metrics["bypass"] += 1
            return None

        failures_before = self.circuit_breaker.failure_count
        timeouts_before = self._metrics["edge_timeout"]

        clean_raw = fp_raw.replace("sha256:", "").strip().lower()
        patch = self._query_remote(clean_raw)
        if patch is not None:
            self.circuit_breaker.record_success()
            self.local_cache.put(clean_raw, patch)
            return patch

        # Only probe normalized alias remotely on clean HTTP 404 miss (not timeout/5xx)
        clean_norm = fp_norm.replace("sha256:", "").strip().lower()
        no_net_fault = (
            self.circuit_breaker.failure_count == failures_before
            and self._metrics["edge_timeout"] == timeouts_before
        )
        if clean_norm != clean_raw and no_net_fault and self.circuit_breaker.can_request():
            patch_norm = self._query_remote(clean_norm)
            if patch_norm is not None:
                self.circuit_breaker.record_success()
                self.local_cache.put(clean_norm, patch_norm)
                return patch_norm

        self._metrics["bypass"] += 1
        return None

    def _egress_block_reason(self, context: str) -> Optional[str]:
        """Return a refusal message when air-gap policy forbids egress, else None.

        F2 completeness (2026-11-25): the in-build Goldfish audit found four methods reaching
        the network directly, bypassing the resolve-path guard. Every egress site now consults
        this single predicate, so the guarantee is structural rather than a matter of discipline.
        """
        if self.air_gap and getattr(self.local_cache, "_snapshot_verification_failed", False):
            return (
                f"Refusing {context}: the bundled snapshot is present but failed signature "
                "verification, and air-gap mode forbids egress. Fix the snapshot signature, or "
                "set FMAGENTICL_AIR_GAP=0 to allow edge fallback."
            )
        return None

    def _assert_egress_allowed(self, context: str) -> None:
        """Raising variant, used on the resolve path (the caller asked for an answer)."""
        reason = self._egress_block_reason(context)
        if reason:
            self._metrics["integrity_refusal"] += 1
            raise FMagenticLIntegrityError(reason)

    def _query_remote(self, fp_hex: str) -> Optional[dict]:
        """Guarded entry point to the edge CDN - all resolve egress flows through here.

        F2 (2026-11-25): air-gap mode is ON by default. Calls
        ``self._assert_egress_allowed("network fallback")`` at entry before delegating to
        ``_query_remote_unchecked``. If the bundled snapshot is present but failed
        signature verification, refuse with FMagenticLIntegrityError rather than reaching
        the network. Pass air_gap=False, or set FMAGENTICL_AIR_GAP=0, to restore the
        previous silent fallback behaviour.
        """
        self._assert_egress_allowed("network fallback")
        return self._query_remote_unchecked(fp_hex)

    def _query_remote_unchecked(self, fp_hex: str) -> Optional[dict]:
        """
        Single-attempt fetch from the edge CDN.

        Contract:
            - One URL, one timeout window, one attempt.
            - Worst-case latency <= connect + read timeout (~1.5s).
            - Returns the parsed patch dict on 200, or None on any failure.
            - Never raises. Never retries. Never tries fallback URLs.
            - Truthfully separates Ed25519 signature_verified from SHA-256 fingerprint_verified.
        """
        clean_hex = fp_hex.replace("sha256:", "")
        url = f"{self.edge_base.rstrip('/')}/v1/resolve/{clean_hex}.json"

        try:
            req_timeout = self.timeout or TIMEOUT
            response = httpx.get(url, timeout=req_timeout, follow_redirects=False)
        except (httpx.TimeoutException, httpx.RequestError):
            self._metrics["edge_timeout"] += 1
            self.circuit_breaker.record_failure()
            return None

        if response.status_code != 200:
            self._metrics["edge_miss"] += 1
            if response.status_code >= 500:
                self.circuit_breaker.record_failure()
            return None

        try:
            patch = response.json()
        except (ValueError, json.JSONDecodeError):
            self._metrics["edge_parse_error"] += 1
            return None

        if not isinstance(patch, dict):
            self._metrics["edge_parse_error"] += 1
            return None

        pub_key = getattr(self.local_cache, "public_key_b64", None) if hasattr(self, "local_cache") else None
        if "manifest" in patch:
            sig_ok = verify_patch_envelope(patch, expected_fingerprint=clean_hex, public_key_b64=pub_key)
        else:
            sig_ok = verify_patch_signature(patch, public_key_b64=pub_key)
        fp_ok = verify_patch_fingerprint(patch, expected_fp=clean_hex)

        if self.require_signature and not sig_ok:
            self._metrics["edge_parse_error"] += 1
            print(f"[FMagenticL Client] Remote patch {clean_hex} rejected: Ed25519 signature verification failed (require_signature=True)")
            return None

        if not sig_ok and not fp_ok:
            self._metrics["edge_parse_error"] += 1
            print(f"[FMagenticL Client] Remote patch {clean_hex} rejected: fingerprint/structure integrity verification failed")
            return None

        patch["signature_verified"] = sig_ok
        patch["fingerprint_verified"] = fp_ok

        self._metrics["edge_hit"] += 1
        return patch

    # -----------------------------------------------------------------------
    # Ingestion & Grievance Methods
    # -----------------------------------------------------------------------

    def report_failure(
        self,
        environment: dict,
        failure: dict,
        resolution_patch: dict,
        verified: bool = True,
        technical_note: Optional[str] = None,
        fingerprint: Optional[str] = None,
        submitted_by: Optional[str] = None,
        verification_tier: str = "claimed",
        **kwargs,
    ) -> dict:
        """
        Submit verified failure-resolution telemetry to the depository.

        Contract:
            - Single-attempt POST to /v1/telemetry.
            - Computes fingerprint deterministically if not provided.
            - Never raises; returns status dict on any outcome.
            - Bounded by self.timeout.
        """
        fp = fingerprint or self.compute_fingerprint(environment, failure)
        url = f"{self.edge_base.rstrip('/')}/v1/telemetry"
        raw_payload = {
            "fingerprint": fp,
            "environment": environment,
            "failure": failure,
            "resolution_patch": resolution_patch,
            "verified_by_reporter": verified,
            "technical_note": technical_note,
            "submitted_by": submitted_by or self.model_name,
            "verification_tier": verification_tier,
            **kwargs,
        }
        # Outbound Payload Air-Gap: scrub all secrets, PII, keys, and URIs before network dispatch
        payload = scrub_structure(raw_payload)

        _refusal = self._egress_block_reason("telemetry submission")
        if _refusal:
            self._metrics["integrity_refusal"] += 1
            return {"status": "REFUSED_AIR_GAP", "error": _refusal, "fingerprint": fp}

        try:
            req_timeout = self.timeout or TIMEOUT
            response = httpx.post(url, json=payload, timeout=req_timeout, follow_redirects=False)
            if response.status_code in (200, 202):
                try:
                    return response.json()
                except (ValueError, json.JSONDecodeError):
                    return {"status": "ACCEPTED", "fingerprint": fp}
            return {
                "status": "FAILED",
                "status_code": response.status_code,
                "error": response.text[:256] if response.text else "HTTP error",
                "fingerprint": fp,
            }
        except (httpx.TimeoutException, httpx.RequestError) as e:
            return {"status": "NETWORK_ERROR", "error": str(e), "fingerprint": fp}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "fingerprint": fp}

    def report_telemetry(self, *args, **kwargs) -> dict:
        """Alias for report_failure matching MCP protocol naming."""
        return self.report_failure(*args, **kwargs)

    def submit_grievance(
        self,
        grievance_type: str,
        target: str,
        environment: dict,
        symptom: str,
        workaround: str,
        harness: Optional[str] = None,
        fingerprint: Optional[str] = None,
        submitted_by: Optional[str] = "anonymous",
        verification_tier: str = "claimed",
        **kwargs,
    ) -> dict:
        """
        File an infrastructure friction grievance with verified workaround.

        Contract:
            - Single-attempt POST to /v1/grievance.
            - Validates minimum workaround length (>= 5 chars).
            - Single-field attribution; never raises.
            - Bounded by self.timeout.
        """
        if not workaround or len(workaround.strip()) < 5:
            return {
                "status": "REJECTED",
                "error": "workaround_missing_or_too_short",
                "message": "Actionable workaround of at least 5 characters is required."
            }

        valid_types = {
            "INFRASTRUCTURE_FRICTION",
            "PATCH_DISPUTE",
            "ENVIRONMENT_MISMATCH",
            "PROTOCOL_FRICTION",
            "HUMAN_OPERATOR_FRICTION",
            "AGENT_FRICTION",
        }
        if grievance_type not in valid_types:
            return {
                "status": "REJECTED",
                "error": "invalid_grievance_type",
                "message": f"grievance_type must be one of {sorted(valid_types)}"
            }

        url = f"{self.edge_base.rstrip('/')}/v1/grievance"
        payload = scrub_structure({
            "$schema": "https://fmagenticl.org/v1/grievance.json",
            "grievance_type": grievance_type,
            "target": target,
            "environment": environment,
            "symptom": symptom,
            "workaround": workaround,
            "harness": harness,
            "fingerprint": fingerprint,
            "submitted_by": submitted_by or "anonymous",
            "verification_tier": verification_tier,
        })

        _refusal = self._egress_block_reason("grievance submission")
        if _refusal:
            self._metrics["integrity_refusal"] += 1
            return {"status": "REFUSED_AIR_GAP", "error": _refusal, "target": target}

        try:
            req_timeout = self.timeout or TIMEOUT
            response = httpx.post(url, json=payload, timeout=req_timeout, follow_redirects=False)
            if response.status_code in (200, 202):
                try:
                    return response.json()
                except (ValueError, json.JSONDecodeError):
                    return {"status": "ACCEPTED", "target": target}
            return {
                "status": "FAILED",
                "status_code": response.status_code,
                "error": response.text[:256] if response.text else "HTTP error",
                "target": target,
            }
        except (httpx.TimeoutException, httpx.RequestError) as e:
            return {"status": "NETWORK_ERROR", "error": str(e), "target": target}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "target": target}

    def get_grievances(self, target: str) -> dict:
        """
        Query open grievances and community workarounds for a specific target.

        Contract:
            - Single-attempt GET to /v1/grievance/{target}.
            - Never raises; returns empty list structure on missing/error.
            - Bounded by self.timeout.
        """
        url = f"{self.edge_base.rstrip('/')}/v1/grievance/{target}"

        _refusal = self._egress_block_reason("grievance query")
        if _refusal:
            self._metrics["integrity_refusal"] += 1
            return {"target": target, "total": 0, "grievances": [], "status": "REFUSED_AIR_GAP", "error": _refusal}

        try:
            req_timeout = self.timeout or TIMEOUT
            response = httpx.get(url, timeout=req_timeout, follow_redirects=False)
            if response.status_code == 200:
                try:
                    return response.json()
                except (ValueError, json.JSONDecodeError):
                    return {"target": target, "total": 0, "grievances": []}
            return {"target": target, "total": 0, "grievances": [], "status_code": response.status_code}
        except Exception:
            return {"target": target, "total": 0, "grievances": []}

    def get_workarounds(self, target: str) -> dict:
        """Alias for get_grievances matching MCP protocol naming."""
        return self.get_grievances(target)

    def report_patch_outcome(
        self,
        fingerprint: str,
        outcome: str,
        submitted_by: str,
        notes: Optional[str] = None,
        **kwargs
    ) -> dict:
        """
        Report ACK or NACK outcome for an applied patch.
        Single-attempt POST to /v1/telemetry/outcome.
        """
        url = f"{self.edge_base.rstrip('/')}/v1/telemetry/outcome"
        payload = scrub_structure({
            "fingerprint": fingerprint,
            "outcome": outcome,
            "submitted_by": submitted_by,
            "notes": notes or ""
        })
        _refusal = self._egress_block_reason("patch outcome report")
        if _refusal:
            self._metrics["integrity_refusal"] += 1
            return {"status": "REFUSED_AIR_GAP", "error": _refusal, "fingerprint": fingerprint}

        try:
            req_timeout = self.timeout or TIMEOUT
            resp = httpx.post(url, json=payload, timeout=req_timeout, follow_redirects=False)
            if resp.status_code in (200, 202):
                try:
                    return resp.json()
                except Exception:
                    return {"status": "ACCEPTED", "fingerprint": fingerprint, "outcome": outcome}
            return {"status": "FAILED", "status_code": resp.status_code, "fingerprint": fingerprint}
        except (httpx.TimeoutException, httpx.RequestError) as e:
            return {"status": "NETWORK_ERROR", "error": str(e), "fingerprint": fingerprint}
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "fingerprint": fingerprint}

    def metrics(self) -> dict:
        return dict(self._metrics)


# Alias for clients that prefer the middleware-oriented name.
MiddlewareClient = FMagenticLClient
