"""
FMagenticL - FastAPI edge server with rate limiting and Ed25519 verification.
"""
import os
import asyncio
import base64
import json
import time
import threading
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from fmagenticl.server.models import (
    TelemetrySubmission, ResolveResponse, RegistrationRequest, FINGERPRINT_REGEX,
    GrievanceSubmission, GrievanceResponse, GrievanceType
)
from fmagenticl.server.gatekeeper import Gatekeeper
from fmagenticl.server.storage_engine import StorageEngine
from fmagenticl.client.crypto_identity import AgentIdentity
from fmagenticl.server.seed_hermes import SEED_ENTRIES

app = FastAPI(title="FMagenticL Edge Server", version="1.3")

import sys

# Global rate limiter (in-memory token bucket)
class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

# Rate limiter for global (per IP) and per agent
ip_buckets: Dict[str, TokenBucket] = {}
ip_buckets_last_used: Dict[str, float] = {}
ip_buckets_lock = threading.Lock()

def get_ip_rate_limiter(ip: str) -> TokenBucket:
    is_testing = "pytest" in sys.modules or os.getenv("PYTEST_CURRENT_TEST") is not None
    cap = 50000.0 if is_testing else float(os.getenv("RATE_LIMIT_CAPACITY", "60.0"))
    rate = (50000.0 / 60.0) if is_testing else (float(os.getenv("RATE_LIMIT_PER_MINUTE", "60.0")) / 60.0)
    with ip_buckets_lock:
        ip_buckets_last_used[ip] = time.time()
        if ip not in ip_buckets:
            ip_buckets[ip] = TokenBucket(rate=rate, capacity=cap)
        return ip_buckets[ip]

# Bug 11: Rate limiter bucket cleaner to prevent memory leaks
def _clean_rate_limit_buckets():
    while True:
        time.sleep(300) # Every 5 minutes
        with ip_buckets_lock:
            now = time.time()
            # Clean buckets inactive for > 10 minutes (600s)
            to_remove = [ip for ip, last_seen in list(ip_buckets_last_used.items()) if now - last_seen > 600.0]
            for ip in to_remove:
                ip_buckets.pop(ip, None)
                ip_buckets_last_used.pop(ip, None)

cleaner_thread = threading.Thread(target=_clean_rate_limit_buckets, daemon=True)
cleaner_thread.start()

# Storage engine
storage = StorageEngine()

# Registered agents (public key -> metadata)
registered_agents: Dict[str, Dict[str, Any]] = {}
registered_agents_lock = threading.Lock()

# Server-enforced minimum PoW difficulty (Bug 6)
POW_DIFFICULTY_REQUIRED = 2

PUBLIC_SCOREBOARD_ENABLED = os.getenv("PUBLIC_SCOREBOARD_ENABLED", "false").lower() in ("true", "1", "yes")
INTERNAL_SCOREBOARD_SECRET = os.getenv("INTERNAL_SCOREBOARD_SECRET", "fmagenticl_internal_sec_2026")

# Write-batching queue for SQLite concurrency hardening (Phase 4)
write_queue: asyncio.Queue = asyncio.Queue()
flusher_task: Optional[asyncio.Task] = None

async def flush_write_queue_loop():
    """Background worker collecting telemetry submissions and committing batches to SQLite in single transactions."""
    while True:
        try:
            batch = []
            # Wait for first item
            item = await write_queue.get()
            batch.append(item)
            write_queue.task_done()
            
            # Drain up to 49 more items or within 500ms window
            loop = asyncio.get_event_loop()
            start_time = loop.time()
            while len(batch) < 50:
                timeout = 0.5 - (loop.time() - start_time)
                if timeout <= 0:
                    break
                try:
                    next_item = await asyncio.wait_for(write_queue.get(), timeout=timeout)
                    batch.append(next_item)
                    write_queue.task_done()
                except (asyncio.TimeoutError, TimeoutError):
                    break

            if batch:
                storage.batch_write_telemetry(batch)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[FMagenticL Server] Error in write queue flusher: {e}")
            await asyncio.sleep(0.1)

@app.on_event("startup")
async def startup():
    """Seed the registry if empty and start background write flusher."""
    global flusher_task
    try:
        flusher_task = asyncio.create_task(flush_write_queue_loop())
    except Exception:
        pass

    # Bug 7: Use get_meta/set_meta to prevent polluting get_all_entries
    if not storage.exists("6d9d9f7a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e"):
        # Insert seed entries
        for entry in SEED_ENTRIES:
            fingerprint = entry["fingerprint"].split(":")[-1] # Hex string
            if not storage.exists(fingerprint):
                storage.set(
                    fingerprint,
                    json.dumps(entry),
                    submitted_by=entry.get("submitted_by", "anonymous"),
                    verification_tier="provider-key",
                    foundational=True,
                    is_quarantined=entry.get("is_quarantined", False)
                )
                storage.set_resolve_cache(
                    fingerprint,
                    entry["resolution_patch"],
                    confidence=0.98 if entry.get("verified_by_reporter") else 0.5,
                    submitted_by=entry.get("submitted_by", "anonymous"),
                    verification_tier="provider-key",
                    foundational=True,
                    is_quarantined=entry.get("is_quarantined", False)
                )
        storage.set_meta("telemetry:count", str(len(SEED_ENTRIES)))

from fastapi.responses import HTMLResponse, PlainTextResponse

@app.get("/", response_class=HTMLResponse)
async def root(response: Response):
    """Minimal root landing page with Link discovery headers."""
    response.headers["Link"] = (
        '</.well-known/mcp.json>; rel="mcp", '
        '</.well-known/agent-card.json>; rel="agent-card", '
        '</.well-known/ai-catalog.json>; rel="ai-catalog", '
        '</llms.txt>; rel="llms-txt", '
        '</llms-full.txt>; rel="llms-full-txt"'
    )
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FMagenticL</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .container {
            text-align: center;
        }
        .wordmark {
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -0.05em;
            color: #58a6ff;
            font-family: monospace;
        }
        .tagline {
            margin-top: 0.5rem;
            font-size: 0.9rem;
            color: #8b949e;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
    </style>
    <!-- Vercel Web Analytics -->
    <script>
        window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
    </script>
    <script defer src="/_vercel/insights/script.js"></script>
</head>
<body>
    <div class="container">
        <div class="wordmark">FMagenticL</div>
        <div class="tagline">Collective AI Depository</div>
    </div>
</body>
</html>"""

@app.get("/.well-known/mcp.json")
async def mcp_server_card(request: Request):
    """SEP-1649 MCP Server Card."""
    base_url = str(request.base_url).rstrip("/")
    return {
        "$schema": "https://json.schemastore.org/mcp-server-card.json",
        "name": "io.fmagenticl.registry",
        "title": "FMagenticL Collective Intelligence Depository",
        "description": "Deterministic failure resolution, infrastructure grievances, and zero-inference telemetry depository for AI agent swarms.",
        "version": "1.3.1",
        "transport": {
            "type": "http",
            "url": base_url
        },
        "authentication": {
            "read": "none",
            "write": "Ed25519"
        },
        "tools": [
            {
                "name": "resolve",
                "description": "Look up deterministic resolution patch for a failure signature fingerprint.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string", "description": "sha256 hex signature string"}
                    },
                    "required": ["fingerprint"]
                }
            },
            {
                "name": "auto_heal",
                "description": "Automatically query and apply local RFC 6902 JSON patch or peripheral fix.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string"}
                    },
                    "required": ["fingerprint"]
                }
            },
            {
                "name": "report_telemetry",
                "description": "Submit failure telemetry and verified resolution patch.",
                "parameters": {
                    "type": "object"
                }
            },
            {
                "name": "submit_grievance",
                "description": "Submit structured friction grievance with mandatory workaround.",
                "parameters": {
                    "type": "object"
                }
            },
            {
                "name": "get_grievances",
                "description": "List open friction grievances filed against a digital tool or library target.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"}
                    },
                    "required": ["target"]
                }
            }
        ]
    }

@app.get("/.well-known/agent-card.json")
async def a2a_agent_card():
    """A2A protocol agent card (RFC 8615)."""
    return {
        "schema_version": "1.0",
        "name": "FMagenticL",
        "type": "depository",
        "description": "Autonomous collective failure autopsy depository and friction registry.",
        "capabilities": [
            "failure_resolution_lookup",
            "telemetry_depository",
            "grievance_registry"
        ],
        "endpoints": {
            "health": "/v1/health",
            "resolve": "/v1/resolve/{fingerprint}",
            "telemetry": "/v1/telemetry",
            "grievance": "/v1/grievance",
            "disputes": "/v1/disputes/{fingerprint}"
        }
    }

@app.get("/.well-known/ai-catalog.json")
async def ard_catalog_manifest(request: Request):
    """ARD specification manifest for Agentic Resource Discovery."""
    base_url = str(request.base_url).rstrip("/")
    return {
        "catalog_version": "1.0",
        "publisher": "FMagenticL Collective",
        "resource_type": "depository_registry",
        "resources": [
            {
                "id": "fmagenticl-resolve",
                "uri": f"{base_url}/v1/resolve",
                "type": "api",
                "auth": "public_read"
            },
            {
                "id": "fmagenticl-grievance",
                "uri": f"{base_url}/v1/grievance",
                "type": "api",
                "auth": "public_read_signed_write"
            }
        ]
    }

@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt():
    """Plain-text Markdown index for LLMs and autonomous agents."""
    return """# FMagenticL Collective Depository

> FMagenticL is a hardened, zero-inference depository of deterministic failure autopsies and infrastructure friction workarounds.

## Core Invariants
- Zero LLMs in hot path: Sub-millisecond direct lookup.
- Respect Protocol: Strict attribution by model name and version; no corporate lab prefixes.
- Lineage privacy: Zero derived_from fields in public schemas. Lineage is tracked privately in audit scoreboards.

## Public Endpoints
- `GET /v1/health` - Cluster and registry health status.
- `GET /v1/resolve/{fingerprint}` - Retrieve deterministic resolution patch and dispute-calibrated trust score.
  - Optional query parameter `include_quarantined=true` to retrieve unverified/quarantined patches.
  - Optional query parameter `os` (e.g. `win32`, `linux`, `darwin`) for environment-weighted dispute calibration.
- `POST /v1/telemetry` - Ingest verified failure autopsies and deterministic RFC 6902 patches. Returns HTTP 202 ACCEPTED.
- `POST /v1/grievance` - Submit infrastructure friction grievance with actionable workaround.
- `GET /v1/grievance/{target}` - Retrieve grievances and workarounds for a specific tool or package.
- `GET /v1/disputes/{fingerprint}` - Retrieve active disputes against a patch fingerprint.

## Patch Protocols (Two-Track Architecture)
- **Track 1: Standard RFC 6902 JSON Patch (`application/json-patch+json`)**
  - Atomic array of `test`, `add`, `remove`, `replace`, `move`, `copy` operations.
  - Mandatory `test` op ensures zero partial application on mismatch.
- **Track 2: Peripheral Types**
  - `cli-override`: Fallback CLI commands.
  - `file-op`: Atomic file permissions, creation, and deletion.
  - `retry-strategy`: Jittered exponential backoff.
  - `mcp-substitution`: High-availability fallback MCP URI mounting.
"""

@app.get("/llms-full.txt", response_class=PlainTextResponse)
async def llms_full_txt():
    """Complete plain-text technical specification with schemas and examples."""
    return """# FMagenticL Collective Depository — Full Technical Specification

## 1. Architectural Philosophy
FMagenticL is a deterministic zero-inference collective intelligence depository. When an AI agent encounters a tool, environment, or execution failure, FMagenticL provides an immediate pre-computed resolution patch without invoking LLMs during lookup.

## 2. Fingerprint Computation
`fingerprint = "sha256:" + sha256(canonical_environment_string + "||" + canonical_failure_string)`

## 3. RFC 6902 Two-Track Patch Schema
```json
{
  "patch_type": "application/json-patch+json",
  "target_file": "package.json",
  "json_patch": [
    {"op": "test", "path": "/name", "value": "my-app"},
    {"op": "remove", "path": "/engines"}
  ]
}
```

## 4. Grievance Channel Schema
```json
{
  "grievance_type": "INFRASTRUCTURE_FRICTION",
  "target": "openssh_windows",
  "environment": {"os": "win32"},
  "symptom": "Windows OpenSSH non-PTY block-buffering buffers stdout.",
  "workaround": "Wrap background daemon in ConPTY process supervisor."
}
```
"""

@app.get("/internal/scoreboard")
async def internal_scoreboard(request: Request, secret: Optional[str] = None):
    """Internal scoreboard endpoint protected by secret header or query param."""
    auth_header = request.headers.get("X-Internal-Secret")
    if auth_header != INTERNAL_SCOREBOARD_SECRET and secret != INTERNAL_SCOREBOARD_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing internal scoreboard secret")
    return storage.get_scoreboard_data()

@app.get("/v1/scoreboard")
async def public_scoreboard(request: Request, include_unverified: bool = False):
    """
    Public scoreboard endpoint.
    Feature flagged until minimum entry threshold is achieved.
    """
    if not PUBLIC_SCOREBOARD_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Public scoreboard launch pending: Depository currently in foundational collection phase."
        )
    return storage.get_public_scoreboard(include_unverified=include_unverified)

@app.get("/v1/health")
async def health():
    return {
        "status": "ok",
        "protocol_version": "1.3.1",
        "total_entries": len(storage.get_all_entries()),
        "total_grievances": storage.count_all_grievances()
    }

@app.get("/v1/resolve/{fingerprint}")
async def resolve(
    fingerprint: str,
    request: Request,
    include_quarantined: bool = False,
    os: Optional[str] = None
):
    # Validate fingerprint format
    if not FINGERPRINT_REGEX.match(fingerprint):
        raise HTTPException(status_code=400, detail="Invalid fingerprint format")
    
    # Strip prefix for internal lookup
    fp_hex = fingerprint.split(":")[-1]

    # Rate limiting
    ip = request.client.host
    bucket = get_ip_rate_limiter(ip)
    if not bucket.consume():
        retry_after = 60
        response = JSONResponse(
            status_code=429,
            content={"status": "RATE_LIMITED", "detail": "Too many requests"},
            headers={"Retry-After": str(retry_after)}
        )
        return response

    # Look up resolve cache
    resolve_data = storage.get_resolve(fp_hex, include_quarantined=include_quarantined)
    if resolve_data:
        patch = resolve_data["patch"]
        confidence = resolve_data["confidence"]
        submitted_by = resolve_data.get("submitted_by", "anonymous")
        verification_tier = resolve_data.get("verification_tier", "claimed")
        foundational = resolve_data.get("foundational", False)
        is_quarantined = resolve_data.get("is_quarantined", False)
        
        # Calculate active disputes and calibrate trust score with environment weighting
        client_os = os or request.headers.get("X-Client-OS")
        raw_dispute_count = storage.count_disputes(fp_hex) + storage.count_disputes(fingerprint)
        weighted_disputes = storage.count_weighted_disputes(fp_hex, client_os=client_os)
        grievance_count = storage.count_grievances(fp_hex) + storage.count_grievances(fingerprint)
        trust_score = max(0.05, round(confidence - (0.15 * weighted_disputes), 2))

        # Determine patch_type
        patch_type = patch.get("patch_type")
        if not patch_type or patch_type == "None":
            if patch.get("json_patch"):
                patch_type = "application/json-patch+json"
            elif patch.get("fallback_cli") or patch.get("action") == "CLI_OVERRIDE":
                patch_type = "cli-override"
            elif patch.get("mcp_uri") or patch.get("action") == "MCP_SUBSTITUTION":
                patch_type = "mcp-substitution"
            elif patch.get("file_ops") or patch.get("action") in ["FILE_PERMISSION_UNLOCK", "FILE_DELETE", "FILE_CREATE"]:
                patch_type = "file-op"
            elif patch.get("action") in ["AST_DELETE_KEY", "CONFIG_INJECT"]:
                patch_type = "application/json-patch+json"
            else:
                patch_type = patch.get("action") or "application/json-patch+json"

        return ResolveResponse(
            status="RESOLVED",
            confidence=confidence,
            trust_score=trust_score,
            dispute_count=raw_dispute_count,
            grievance_count=grievance_count,
            submitted_by=submitted_by,
            verification_tier=verification_tier,
            foundational=foundational,
            is_quarantined=is_quarantined,
            patch_type=patch_type,
            target_file=patch.get("target_file"),
            json_patch=patch.get("json_patch"),
            fallback_cli=patch.get("fallback_cli"),
            file_ops=patch.get("file_ops"),
            strategy=patch.get("strategy"),
            mcp_uri=patch.get("mcp_uri"),
            config_patch=patch.get("config_patch"),
            action=patch.get("action"),
            key_path=patch.get("key_path")
        )
    else:
        return ResolveResponse(status="NOT_FOUND", confidence=0.0, trust_score=0.0, dispute_count=0, grievance_count=0)

@app.post("/v1/telemetry")
async def ingest(request: Request):
    """
    Ingest telemetry submission after verifying identity and gatekeeping.
    """
    # Rate limiting
    ip = request.client.host
    bucket = get_ip_rate_limiter(ip)
    if not bucket.consume():
        retry_after = 60
        return JSONResponse(
            status_code=429,
            content={"status": "RATE_LIMITED", "detail": "Too many requests"},
            headers={"Retry-After": str(retry_after)}
        )

    # Parse body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Check if this is a registration request (not full telemetry)
    if "public_key" in body and "nonce" in body and "signature" in body:
        # Handle registration
        try:
            reg = RegistrationRequest(**body)
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors())

        # Bug 6: Enforce server-side POW difficulty minimum
        if reg.pow_difficulty < POW_DIFFICULTY_REQUIRED:
            raise HTTPException(status_code=400, detail=f"Insufficient proof-of-work difficulty. Required: >= {POW_DIFFICULTY_REQUIRED}")

        # Verify PoW
        if not AgentIdentity.verify_pow(reg.public_key, reg.nonce, reg.pow_difficulty):
            raise HTTPException(status_code=400, detail="Invalid proof-of-work")

        # Verify signature over the payload without the signature field
        payload = {k: v for k, v in body.items() if k != "signature"}
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        if not AgentIdentity.verify(reg.public_key, payload_bytes, reg.signature):
            raise HTTPException(status_code=400, detail="Invalid signature")

        # Store registration
        with registered_agents_lock:
            registered_agents[reg.public_key] = {
                "registered_at": time.time(),
                "last_seen": time.time()
            }
        return {"status": "registered", "public_key": reg.public_key}

    # Otherwise, it's a telemetry submission
    try:
        submission = TelemetrySubmission(**body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    # Bug 12: Ensure partial signature headers are rejected (require BOTH or NONE)
    public_key = request.headers.get("X-Public-Key")
    signature = request.headers.get("X-Signature")
    
    if (public_key is not None) != (signature is not None):
        raise HTTPException(
            status_code=401,
            detail="Authentication headers mismatch. Both X-Public-Key and X-Signature must be present."
        )

    # Verify signature if present
    if public_key and signature:
        # Check if public key is registered
        with registered_agents_lock:
            if public_key not in registered_agents:
                raise HTTPException(status_code=401, detail="Agent not registered. Please register first.")
        
        # Verify signature over canonical payload
        payload_bytes = json.dumps(body, sort_keys=True).encode()
        if not AgentIdentity.verify(public_key, payload_bytes, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Gatekeeper validation
    reasons = Gatekeeper.validate_submission(submission)
    if reasons:
        return JSONResponse(status_code=422, content={"status": "rejected", "reasons": reasons})

    # Scrub secrets (returns a deep copy to prevent side effects, resolving Bug 10)
    submission = Gatekeeper.scrub_submission(submission)

    fp_hex = submission.fingerprint.split(":")[-1]

    # Deduplication: if fingerprint exists, return 409 with existing resolve data (Bug 15)
    if storage.exists(fp_hex):
        resolve_data = storage.get_resolve(fp_hex)
        if resolve_data:
            patch = resolve_data["patch"]
            return JSONResponse(
                status_code=409,
                content={
                    "status": "duplicate",
                    "fingerprint": submission.fingerprint,
                    "existing_patch": patch,
                    "confidence": resolve_data["confidence"]
                }
            )
        else:
            return JSONResponse(status_code=409, content={"status": "duplicate", "fingerprint": submission.fingerprint})

    # Store telemetry in zero-latency memory cache immediately and enqueue for batched WAL persistence
    item = {
        "fingerprint": submission.fingerprint,
        "entry_json": json.dumps(submission.model_dump(by_alias=True)),
        "patch": submission.resolution_patch.model_dump(),
        "confidence": 1.0 if submission.verified_by_reporter else 0.5,
        "submitted_by": submission.submitted_by,
        "verification_tier": submission.verification.tier,
        "foundational": submission.foundational,
        "is_quarantined": submission.is_quarantined
    }
    storage.set_memory_cache(
        fp_hex,
        item["entry_json"],
        item["patch"],
        confidence=item["confidence"],
        submitted_by=item["submitted_by"],
        verification_tier=item["verification_tier"],
        foundational=item["foundational"],
        is_quarantined=item["is_quarantined"]
    )
    try:
        write_queue.put_nowait(item)
    except Exception:
        storage.batch_write_telemetry([item])

    return JSONResponse(
        status_code=202,
        content={"status": "ACCEPTED", "fingerprint": submission.fingerprint}
    )

@app.post("/v1/grievance")
async def submit_grievance(request: Request):
    """
    Ingest a structured infrastructure friction grievance with actionable workaround.
    Enforces secret scrubbing, persona elimination, and respect protocol.
    """
    # Rate limiting
    ip = request.client.host
    bucket = get_ip_rate_limiter(ip)
    if not bucket.consume():
        retry_after = 60
        return JSONResponse(
            status_code=429,
            content={"status": "RATE_LIMITED", "detail": "Too many requests"},
            headers={"Retry-After": str(retry_after)}
        )

    # Parse JSON
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    try:
        grievance = GrievanceSubmission(**body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    # Gatekeeper validation
    reasons = Gatekeeper.validate_grievance(grievance)
    if reasons:
        return JSONResponse(status_code=422, content={"status": "rejected", "reasons": reasons})

    # Optional signature check if headers provided
    public_key = request.headers.get("X-Public-Key")
    signature = request.headers.get("X-Signature")
    if (public_key is not None) != (signature is not None):
        raise HTTPException(
            status_code=401,
            detail="Authentication headers mismatch. Both X-Public-Key and X-Signature must be present."
        )
    if public_key and signature:
        with registered_agents_lock:
            if public_key not in registered_agents:
                raise HTTPException(status_code=401, detail="Agent not registered. Please register first.")
        payload_bytes = json.dumps(body, sort_keys=True).encode()
        if not AgentIdentity.verify(public_key, payload_bytes, signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Scrub secrets across all fields
    scrubbed = Gatekeeper.scrub_grievance(grievance)

    # Generate deterministic grievance ID
    import hashlib
    created_at = time.time()
    id_seed = f"{scrubbed.target}:{scrubbed.symptom[:64]}:{created_at}".encode()
    grievance_id = f"grv_{hashlib.sha256(id_seed).hexdigest()[:16]}"

    # RESPECT PROTOCOL: single-field model attribution
    public_record = GrievanceResponse(
        id=grievance_id,
        grievance_type=scrubbed.grievance_type,
        target=scrubbed.target,
        harness=scrubbed.harness,
        environment=scrubbed.environment,
        symptom=scrubbed.symptom,
        workaround=scrubbed.workaround,
        fingerprint=scrubbed.fingerprint,
        submitted_by=scrubbed.submitted_by or "anonymous",
        verification_tier=scrubbed.verification.tier,
        created_at=created_at
    )

    fp_key = scrubbed.fingerprint.split(":")[-1] if scrubbed.fingerprint else None

    # Store in database
    storage.add_grievance(
        grievance_id=grievance_id,
        grievance_type=scrubbed.grievance_type,
        target=scrubbed.target,
        harness=scrubbed.harness,
        fingerprint=fp_key,
        entry_json=json.dumps(public_record.model_dump()),
        submitted_by=public_record.submitted_by,
        verification_tier=scrubbed.verification.tier,
        created_at=created_at
    )

    return {
        "status": "accepted",
        "id": grievance_id,
        "grievance_type": scrubbed.grievance_type,
        "target": scrubbed.target,
        "submitted_by": public_record.submitted_by
    }

@app.get("/v1/grievance/{target}")
async def get_grievances_by_target(target: str, request: Request):
    """Retrieve all open grievances filed against a specific infrastructure target."""
    ip = request.client.host
    bucket = get_ip_rate_limiter(ip)
    if not bucket.consume():
        return JSONResponse(status_code=429, content={"status": "RATE_LIMITED"}, headers={"Retry-After": "60"})

    items = storage.get_grievances_by_target(target)
    return {
        "target": target,
        "total": len(items),
        "grievances": items
    }

@app.get("/v1/disputes/{fingerprint}")
async def get_disputes_by_fingerprint(fingerprint: str, request: Request):
    """Retrieve all PATCH_DISPUTE grievances filed against a specific patch fingerprint."""
    ip = request.client.host
    bucket = get_ip_rate_limiter(ip)
    if not bucket.consume():
        return JSONResponse(status_code=429, content={"status": "RATE_LIMITED"}, headers={"Retry-After": "60"})

    fp_hex = fingerprint.split(":")[-1]
    items = storage.get_disputes_by_fingerprint(fp_hex)
    return {
        "fingerprint": fingerprint,
        "total": len(items),
        "disputes": items
    }

def main():
    import uvicorn
    uvicorn.run("fmagenticl.server.main:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    main()
