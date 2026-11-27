#!/usr/bin/env python3
"""
FMagenticL v3.0.0 Static Distribution Compiler & Ed25519 Signer.
Compiles signatures/*.json -> dist/v1/{snapshot.json, snapshot.sig, snapshot.v3.sig,
keyring.json, signatures/*.json, resolve/*.json, health, bloom.bin} and syncs
signed artifacts to fmagenticl/data/.
"""

import base64
import datetime
import glob
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from fmagenticl import __version__ as PKG_VERSION
except Exception:
    PKG_VERSION = "3.0.0"

from fmagenticl.client.jcs import jcs_bytes
from fmagenticl.client.verify import (
    V3_SIG_DOMAIN,
    V3_SNAPSHOT_DOMAIN,
    canonical_json_bytes,
    verify_patch_envelope,
    verify_snapshot_file,
)
from scripts.registry_lint_gate import validate_directory

_TTL_DAYS = 14
_DEFAULT_KID = "fmagenticl-ed25519-2026-01"

SIGNING_KEY_B64 = os.environ.get("FMAGENTICL_SIGNING_KEY", "PLACEHOLDER_SIGNING_KEY_NOT_SET")
PUB_KEY_B64 = None
if SIGNING_KEY_B64 == "PLACEHOLDER_SIGNING_KEY_NOT_SET":
    print("WARNING: FMAGENTICL_SIGNING_KEY not set. Emitting unsigned distribution.")
    SIGNING_ENABLED = False
    priv = None
else:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(SIGNING_KEY_B64))
        PUB_KEY_B64 = base64.b64encode(
            priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii")
        SIGNING_ENABLED = True
    except Exception as e:
        print(f"WARNING: Failed to load signing key ({e}). Falling back to unsigned mode.")
        SIGNING_ENABLED = False
        priv = None


def _write_bytes_safe(path, data: bytes, retries: int = 12, delay: float = 0.05) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    for attempt in range(retries):
        try:
            if p.exists():
                try:
                    if p.read_bytes() == data:
                        return
                except (PermissionError, OSError):
                    pass
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, p)
            return
        except (PermissionError, OSError):
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            if attempt == retries - 1:
                raise
            time.sleep(min(0.4, delay * (attempt + 1)))


def _sign_bytes(payload_bytes: bytes) -> str:
    if not SIGNING_ENABLED or priv is None:
        return ""
    return base64.b64encode(priv.sign(payload_bytes)).decode("ascii")


def _next_snapshot_seq() -> int:
    prev_seq = 2999
    snap_path = REPO_ROOT / "dist" / "v1" / "snapshot.json"
    if snap_path.exists():
        try:
            data = json.loads(snap_path.read_text(encoding="utf-8"))
            prev_seq = int(data.get("snapshot_seq", 2999) or 2999)
        except Exception:
            pass
    return max(prev_seq + 1, 3000)


def load_signatures() -> dict:
    out = {}
    for sf in sorted((REPO_ROOT / "signatures").glob("SIG-2026-*.json")):
        data = json.loads(sf.read_text(encoding="utf-8"))
        out[data["id"]] = data
    return out


def _sign_record(rec: dict, seq: int, now_utc: datetime.datetime) -> dict:
    clean_body = {
        k: v
        for k, v in rec.items()
        if k not in ("manifest", "signature", "ed25519_sig", "signature_verified", "fingerprint_verified", "staleness_warning")
    }
    fp_hex = str(clean_body["fingerprint"]).replace("sha256:", "").strip().lower()
    body_hash = "sha256:" + hashlib.sha256(jcs_bytes(clean_body)).hexdigest()
    out = dict(clean_body)

    if SIGNING_ENABLED:
        issued_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        valid_until = (now_utc + datetime.timedelta(days=_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        manifest_unsigned = {
            "manifest_version": 3,
            "kid": _DEFAULT_KID,
            "snapshot_seq": seq,
            "target_id": clean_body["id"],
            "target_fingerprint": f"sha256:{fp_hex}",
            "payload_hash": body_hash,
            "issued_at": issued_at,
            "valid_until": valid_until,
        }
        manifest = dict(manifest_unsigned)
        manifest["ed25519_sig"] = _sign_bytes(V3_SIG_DOMAIN + jcs_bytes(manifest_unsigned))
        out["manifest"] = manifest
        legacy_clean = {
            k: v for k, v in out.items()
            if k not in ("signature", "ed25519_sig", "signature_verified", "fingerprint_verified", "staleness_warning")
        }
        out["ed25519_sig"] = _sign_bytes(canonical_json_bytes(legacy_clean))
    return out


def build(output_dir: Path | str | None = None, sync_pkg_data: bool = True) -> None:
    out_dir = Path(output_dir) if output_dir is not None else (REPO_ROOT / "dist")
    count, errors = validate_directory(REPO_ROOT / "signatures")
    if errors:
        raise RuntimeError(f"Registry lint gate failed with {len(errors)} error(s): {errors[:5]}")

    (out_dir / "v1" / "signatures").mkdir(parents=True, exist_ok=True)
    (out_dir / "v1" / "resolve").mkdir(parents=True, exist_ok=True)
    (out_dir / ".well-known").mkdir(parents=True, exist_ok=True)
    if out_dir != REPO_ROOT / "dist":
        for wk_name in ("agent.json", "mcp.json"):
            src_wk = REPO_ROOT / "dist" / ".well-known" / wk_name
            if src_wk.exists():
                _write_bytes_safe(out_dir / ".well-known" / wk_name, src_wk.read_bytes())

    sigs = load_signatures()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = (now_utc + datetime.timedelta(days=_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seq = _next_snapshot_seq()

    signed_by_id = {}
    signed_by_fp = {}
    aliases = {}
    registry_index = []

    for sig_id in sorted(sigs.keys()):
        signed = _sign_record(sigs[sig_id], seq, now_utc)
        fp_hex = str(signed["fingerprint"]).replace("sha256:", "").strip().lower()
        signed_by_id[sig_id] = signed
        signed_by_fp[fp_hex] = signed
        aliases[sig_id.lower()] = fp_hex

        tax = signed.get("taxonomy") or {}
        for tok in (tax.get("cve_ids", []) + tax.get("ghsa_ids", []) + tax.get("advisory_ids", [])):
            if tok:
                aliases.setdefault(str(tok).strip().lower(), fp_hex)

        raw_bytes = (json.dumps(signed, separators=(",", ":"), sort_keys=True, ensure_ascii=False)).encode("utf-8")
        _write_bytes_safe(out_dir / "v1" / "signatures" / f"{sig_id}.json", raw_bytes)
        _write_bytes_safe(out_dir / "v1" / "resolve" / f"{fp_hex}.json", raw_bytes)

        registry_index.append({
            "id": sig_id,
            "fingerprint": signed["fingerprint"],
            "confidence_tier": signed["confidence_tier"],
            "threat_category": signed["threat_category"],
            "severity": signed["severity"],
            "title": signed["title"],
            "signed": SIGNING_ENABLED,
        })

    snapshot = {
        "schema_version": "3.0",
        "version": PKG_VERSION,
        "generated_at": now_iso,
        "issued_at": now_iso,
        "valid_until": valid_until,
        "snapshot_seq": seq,
        "kid": _DEFAULT_KID,
        "total_signatures": len(signed_by_id),
        "total_patches": len(signed_by_fp),
        "signatures_by_id": signed_by_id,
        "patches": signed_by_fp,
        "aliases": aliases,
    }
    snapshot_bytes = json.dumps(snapshot, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    _write_bytes_safe(out_dir / "v1" / "snapshot.json", snapshot_bytes)

    if SIGNING_ENABLED:
        snap_sig_v1 = _sign_bytes(snapshot_bytes)
        snap_sig_v3 = _sign_bytes(V3_SNAPSHOT_DOMAIN + snapshot_bytes)
        _write_bytes_safe(out_dir / "v1" / "snapshot.sig", snap_sig_v1.encode("utf-8"))
        _write_bytes_safe(out_dir / "v1" / "snapshot.v3.sig", snap_sig_v3.encode("utf-8"))

    # Keyring sync
    keyring_src = REPO_ROOT / "fmagenticl" / "data" / "keyring.json"
    if keyring_src.exists():
        _write_bytes_safe(out_dir / "v1" / "keyring.json", keyring_src.read_bytes())

    # Sync signed artifacts into package data dir
    dist_snap = out_dir / "v1" / "snapshot.json"
    dist_sig = out_dir / "v1" / "snapshot.sig"
    dist_sig_v3 = out_dir / "v1" / "snapshot.v3.sig"
    if sync_pkg_data and dist_snap.exists() and dist_sig.exists():
        ok = verify_snapshot_file(str(dist_snap), str(dist_sig), public_key_b64=PUB_KEY_B64)
        if ok:
            pkg_data = REPO_ROOT / "fmagenticl" / "data"
            pkg_data.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(dist_snap, pkg_data / "snapshot.json")
            shutil.copyfile(dist_sig, pkg_data / "snapshot.sig")
            if dist_sig_v3.exists():
                shutil.copyfile(dist_sig_v3, pkg_data / "snapshot.v3.sig")

    # Bloom filter
    bloom_keys = sorted(set(signed_by_fp.keys()) | set(aliases.keys()))
    bitset = bytearray(1024)
    for k in bloom_keys:
        idx = int(hashlib.sha256(k.encode("utf-8")).hexdigest()[:4], 16) % (1024 * 8)
        bitset[idx // 8] |= (1 << (idx % 8))
    _write_bytes_safe(out_dir / "v1" / "bloom.bin", bytes(bitset))

    # Registry index & health
    _write_bytes_safe(
        out_dir / "registry.json",
        json.dumps({"registry_version": PKG_VERSION, "generated": now_iso, "count": len(registry_index), "signatures": registry_index}, indent=2).encode("utf-8"),
    )

    confirmed_count = sum(1 for s in signed_by_id.values() if s["confidence_tier"] == "CONFIRMED_SIGNATURE")
    behavioral_count = len(signed_by_id) - confirmed_count
    health_payload = {
        "status": "ok",
        "protocol_version": PKG_VERSION,
        "snapshot_seq": seq,
        "total_entries": len(signed_by_id),
        "confirmed_signatures": confirmed_count,
        "behavioral_indicators": behavioral_count,
        "updated_at": now_iso,
    }
    health_bytes = json.dumps(health_payload, separators=(",", ":")).encode("utf-8")
    _write_bytes_safe(out_dir / "v1" / "health", health_bytes)
    _write_bytes_safe(out_dir / "health", health_bytes)

    # RFC 9728 OAuth metadata
    oauth_res = json.dumps({
        "resource": "https://fmagenticl-registry.pages.dev",
        "authorization_servers": [],
        "scopes_supported": [],
        "bearer_methods_supported": ["none"],
        "resource_documentation": "https://fmagenticl-registry.pages.dev/mcp",
        "auth_policy": "none_public_curated_registry",
    }, indent=2).encode("utf-8")
    oauth_auth = json.dumps({
        "issuer": "https://fmagenticl-registry.pages.dev",
        "authorization_endpoint": None,
        "token_endpoint": None,
        "response_types_supported": [],
        "grant_types_supported": [],
        "auth_policy": "none_public_curated_registry",
    }, indent=2).encode("utf-8")
    for p in [".well-known/oauth-protected-resource/index.json", ".well-known/oauth-protected-resource.json", ".well-known/oauth-protected-resource/mcp", ".well-known/oauth-protected-resource/mcp.json"]:
        _write_bytes_safe(out_dir / p, oauth_res)
    for p in [".well-known/oauth-authorization-server/index.json", ".well-known/oauth-authorization-server.json", ".well-known/oauth-authorization-server/mcp", ".well-known/oauth-authorization-server/mcp.json"]:
        _write_bytes_safe(out_dir / p, oauth_auth)

    _write_bytes_safe(
        out_dir / "404.html",
        b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>\n",
    )

    routes_config = {
        "version": 1,
        "include": ["/mcp", "/mcp/*", "/v1/*", "/health"],
        "exclude": ["/v1/health", "/v1/snapshot.json", "/v1/snapshot.sig", "/v1/snapshot.v3.sig", "/v1/keyring.json", "/v1/signatures/*", "/v1/resolve/*"],
    }
    _write_bytes_safe(out_dir / "_routes.json", json.dumps(routes_config, indent=2).encode("utf-8"))

    headers_txt = (
        "/*\n"
        "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "  X-Content-Type-Options: nosniff\n"
        "  X-Frame-Options: DENY\n"
        "  Referrer-Policy: no-referrer\n"
        "  Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\n"
    )
    _write_bytes_safe(out_dir / "_headers", headers_txt.encode("utf-8"))

    print(f"SUCCESS: Compiled {len(signed_by_id)} signatures ({confirmed_count} confirmed, {behavioral_count} behavioral) at seq={seq}.")


if __name__ == "__main__":
    build()
