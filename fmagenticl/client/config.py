"""
Configuration for the FMagenticL client SDK.

All values can be overridden via environment variables. Defaults point at
placeholders so that a fresh install fails loudly rather than silently
querying the wrong endpoint.
"""

import os

# Edge CDN base URL — points at the static patch distribution.
# Production value: the Cloudflare Pages URL (e.g. https://fmagenticl.pages.dev).
EDGE_BASE = os.environ.get("FMAGENTICL_EDGE_BASE", "https://fmagenticl-registry.pages.dev")

# Path to the bundled snapshot file. Populated by the SDK at install time.
# If missing, the SDK operates in edge-only mode.
SNAPSHOT_PATH = os.environ.get("FMAGENTICL_SNAPSHOT_PATH", "snapshot.json")

# Path to the local delta cache. Written to disk on edge fetches.
DELTA_CACHE_PATH = os.environ.get(
    "FMAGENTICL_DELTA_CACHE_PATH",
    os.path.join(os.path.expanduser("~"), ".fmagenticl", "delta_cache.json"),
)

# Base64-encoded Ed25519 public key for verifying signed snapshots and deltas.
FMAGENTICL_PUBLIC_KEY = os.environ.get(
    "FMAGENTICL_PUBLIC_KEY",
    "guknKNLrBRrjQ83nSrj3V5+fysNYf99X9w7MdOdqB5w=",
)

# HTTP timeout profile. Total worst-case latency for a single request is
# bounded by (connect + read) = 1.5 seconds. This is the SLA the client
# guarantees to the host agent runtime.
import httpx  # noqa: E402

TIMEOUT = httpx.Timeout(1.0, connect=0.5, read=1.0, write=0.5, pool=0.5)
