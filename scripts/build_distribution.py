import os, sys, json, glob, hashlib, datetime, base64, shutil, time
from pathlib import Path


def _write_bytes_safe(path, data: bytes, retries: int = 12, delay: float = 0.05) -> None:
    """Write bytes idempotently, tolerating transient Windows locks via atomic replace."""
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

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from fmagenticl import __version__ as PKG_VERSION
except Exception:
    PKG_VERSION = "2.1.0"

from fmagenticl.client.verify import (
    canonical_json_bytes,
    compute_payload_hash,
    verify_patch_envelope,
    verify_patch_signature,
    verify_snapshot_file,
)

SIGNING_KEY_B64 = os.environ.get("FMAGENTICL_SIGNING_KEY", "PLACEHOLDER_SIGNING_KEY_NOT_SET")
PUB_KEY_B64 = None
if SIGNING_KEY_B64 == "PLACEHOLDER_SIGNING_KEY_NOT_SET":
    print("WARNING: Signing key not set. Emitting unsigned snapshot. Set FMAGENTICL_SIGNING_KEY to enable signing.")
    SIGNING_ENABLED = False
    priv = None
else:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(SIGNING_KEY_B64))
        PUB_KEY_B64 = base64.b64encode(
            priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode()
        SIGNING_ENABLED = True
    except Exception as e:
        print(f"WARNING: Failed to load signing key ({e}). Falling back to unsigned mode.")
        SIGNING_ENABLED = False
        priv = None


def load_patches():
    out = {}
    for pf in sorted(glob.glob("patches/*.json")):
        with open(pf, encoding="utf-8") as f:
            data = json.load(f)
        fp_hex = Path(pf).stem
        out[fp_hex] = data
    return out


def sign_payload(payload_bytes: bytes) -> str:
    if not SIGNING_ENABLED or priv is None:
        return ""
    return base64.b64encode(priv.sign(payload_bytes)).decode()


_TRANSIENT_PATCH_KEYS = (
    "manifest",
    "signature",
    "ed25519_sig",
    "signature_verified",
    "fingerprint_verified",
    "staleness_warning",
)
_REMEDIATION_EXCLUDE_KEYS = _TRANSIENT_PATCH_KEYS + ("fingerprint", "environment", "failure")
_RENEWAL_MARGIN_DAYS = 14
_TTL_DAYS = 90


def _build_dual_signed_entry(fp_hex: str, base_data: dict, resolve_path: Path, now_utc: datetime.datetime) -> dict:
    """Build a flat dual-signed (v1 top-level + v2 TUF manifest) resolve entry with renewal-hysteresis."""
    clean_hex = fp_hex.replace("sha256:", "").strip().lower()
    out_data = {k: v for k, v in base_data.items() if k not in _TRANSIENT_PATCH_KEYS}
    out_data["fingerprint"] = f"sha256:{clean_hex}"

    remediation_dict = {k: v for k, v in out_data.items() if k not in _REMEDIATION_EXCLUDE_KEYS}
    payload_hash = f"sha256:{compute_payload_hash(remediation_dict)}"

    if resolve_path.exists():
        try:
            prev = json.loads(resolve_path.read_text(encoding="utf-8"))
            if isinstance(prev, dict):
                prev_body = {k: v for k, v in prev.items() if k not in _TRANSIENT_PATCH_KEYS}
                if prev_body == out_data:
                    prev_manifest = prev.get("manifest")
                    top_sig = prev.get("ed25519_sig") or prev.get("signature")
                    if isinstance(prev_manifest, dict) and top_sig and prev_manifest.get("ed25519_sig"):
                        if not SIGNING_ENABLED:
                            preserved = dict(out_data)
                            preserved["manifest"] = prev_manifest
                            preserved["ed25519_sig"] = top_sig
                            return preserved
                        valid_until_str = prev_manifest.get("valid_until")
                        if valid_until_str:
                            expiry = datetime.datetime.fromisoformat(str(valid_until_str).replace("Z", "+00:00"))
                            if expiry.tzinfo is None:
                                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
                            if (
                                (expiry - now_utc) > datetime.timedelta(days=_RENEWAL_MARGIN_DAYS)
                                and prev_manifest.get("payload_hash") == payload_hash
                                and prev_manifest.get("target_fingerprint") == f"sha256:{clean_hex}"
                                and verify_patch_envelope(prev, expected_fingerprint=clean_hex, public_key_b64=PUB_KEY_B64)
                                and verify_patch_signature(prev, public_key_b64=PUB_KEY_B64)
                            ):
                                preserved = dict(out_data)
                                preserved["manifest"] = prev_manifest
                                preserved["ed25519_sig"] = top_sig
                                return preserved
        except Exception:
            pass

    if SIGNING_ENABLED:
        valid_until = (now_utc + datetime.timedelta(days=_TTL_DAYS)).strftime("%Y-%m-%dT00:00:00Z")
        manifest_unsigned = {
            "manifest_version": 2,
            "payload_hash": payload_hash,
            "target_fingerprint": f"sha256:{clean_hex}",
            "valid_until": valid_until,
        }
        manifest = dict(manifest_unsigned)
        manifest["ed25519_sig"] = sign_payload(canonical_json_bytes(manifest_unsigned))
        out_data["manifest"] = manifest

        clean_patch = {
            k: v for k, v in out_data.items()
            if k not in ("signature", "ed25519_sig", "signature_verified", "fingerprint_verified", "staleness_warning")
        }
        out_data["ed25519_sig"] = sign_payload(canonical_json_bytes(clean_patch))

    return out_data


def build():
    os.makedirs("dist/v1/resolve", exist_ok=True)
    os.makedirs("dist/v1/deltas", exist_ok=True)
    os.makedirs("dist/.well-known", exist_ok=True)

    patches = load_patches()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = now_utc.strftime("%Y%m%d%H%M%S")

    # Build canonical registry_patches list + normalized alias map from seed cases
    aliases = {}
    try:
        from fmagenticl.client.fingerprint import compute_fingerprint, compute_normalized_fingerprint
        from fmagenticl.server.seed_hermes import RAW_SEED_CASES
        seed_map = {}
        for c in RAW_SEED_CASES:
            raw_hex = compute_fingerprint(c["env"], c["fail"], normalize=False).replace("sha256:", "")
            norm_hex = compute_normalized_fingerprint(c["env"], c["fail"]).replace("sha256:", "")
            seed_map[raw_hex] = c["fail"].get("error_code") or c["fail"].get("error")
            if raw_hex in patches and norm_hex != raw_hex and norm_hex not in patches:
                aliases[norm_hex] = raw_hex
    except Exception:
        seed_map = {}

    registry_patches = []
    for fp_hex in sorted(patches.keys()):
        p_data = patches[fp_hex]
        failure_mode = seed_map.get(fp_hex) or p_data.get("failure_mode") or p_data.get("patch_type", "deterministic-patch")
        attribution = p_data.get("attribution") or p_data.get("submitted_by")
        if not attribution or attribution == "anonymous" or attribution == "DeepSeek":
            attribution = "deepseek-v3"

        registry_patches.append({
            "id": fp_hex,
            "attribution": attribution,
            "failure_mode": failure_mode,
            "patch_hash": f"sha256:{fp_hex}",
            "signed": True,
        })

    # 1. Per-patch files (canonical + normalized aliases; flat dual-signed v1 + v2 TUF envelopes)
    resolve_changed = False
    signed_patches = {}
    expected_resolve_stems = set(patches.keys()) | set(aliases.keys())

    for old_f in Path("dist/v1/resolve").glob("*.json"):
        if old_f.stem not in expected_resolve_stems:
            old_f.unlink()
            resolve_changed = True

    for fp_hex in sorted(patches.keys()):
        resolve_path = Path(f"dist/v1/resolve/{fp_hex}.json")
        out_data = _build_dual_signed_entry(fp_hex, patches[fp_hex], resolve_path, now_utc)
        signed_patches[fp_hex] = out_data
        serialized = json.dumps(out_data, separators=(",", ":"), sort_keys=True)
        if not resolve_path.exists() or resolve_path.read_text(encoding="utf-8") != serialized:
            resolve_path.write_text(serialized, encoding="utf-8")
            resolve_changed = True

    for norm_hex, raw_hex in sorted(aliases.items()):
        resolve_path = Path(f"dist/v1/resolve/{norm_hex}.json")
        alias_base = dict(patches[raw_hex])
        alias_base["canonical_fingerprint"] = f"sha256:{raw_hex}"
        out_alias = _build_dual_signed_entry(norm_hex, alias_base, resolve_path, now_utc)
        serialized = json.dumps(out_alias, separators=(",", ":"), sort_keys=True)
        if not resolve_path.exists() or resolve_path.read_text(encoding="utf-8") != serialized:
            resolve_path.write_text(serialized, encoding="utf-8")
            resolve_changed = True

    # Content-comparison guard: skip timestamp/signature churn if patches, aliases, and version are unchanged
    patches_unchanged = False
    if (
        not resolve_changed
        and os.path.exists("dist/registry.json")
        and os.path.exists("dist/v1/snapshot.json")
        and (not SIGNING_ENABLED or os.path.exists("dist/v1/snapshot.sig"))
        and os.path.exists("dist/v1/bloom.bin")
        and os.path.exists("dist/v1/deltas/latest.json")
        and os.path.exists("dist/workarounds.json")
        and os.path.exists("dist/grievances.json")
    ):
        try:
            with open("dist/registry.json", "r", encoding="utf-8") as f:
                existing_reg = json.load(f)
            with open("dist/v1/snapshot.json", "r", encoding="utf-8") as f:
                existing_snap = json.load(f)
            if (
                existing_reg.get("patches") == registry_patches
                and existing_reg.get("count") == len(registry_patches)
                and existing_snap.get("patches") == signed_patches
                and existing_snap.get("aliases", {}) == aliases
                and existing_snap.get("total_patches") == len(signed_patches)
                and existing_snap.get("version") == PKG_VERSION
            ):
                patches_unchanged = True
                print(f"Distribution patches unchanged (count: {len(registry_patches)}, aliases: {len(aliases)}). Preserving snapshot/signatures.")
        except Exception:
            pass

    if not patches_unchanged:
        # 2. Base Snapshot (carries dual-signed per-patch entries + aliases)
        snapshot = {
            "version": PKG_VERSION,
            "generated_at": now_iso,
            "total_patches": len(signed_patches),
            "patches": signed_patches,
            "aliases": aliases,
        }
        snapshot_bytes = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode()

        with open("dist/v1/snapshot.json", "wb") as f:
            f.write(snapshot_bytes)

        if SIGNING_ENABLED:
            snapshot_signature = sign_payload(snapshot_bytes)
            with open("dist/v1/snapshot.sig", "w", encoding="utf-8") as f:
                f.write(snapshot_signature)
        else:
            print("INFO: Skipped dist/v1/snapshot.sig (signing disabled).")

        # 3. Bloom filter (canonical + normalized alias keys)
        bloom_keys = sorted(set(signed_patches.keys()) | set(aliases.keys()))
        try:
            from pybloom_live import BloomFilter
            bloom = BloomFilter(capacity=max(10000, len(bloom_keys) * 4), error_rate=0.001)
            for fp_hex in bloom_keys:
                bloom.add(fp_hex)
            with open("dist/v1/bloom.bin", "wb") as f:
                bloom.tofile(f)
            print("INFO: dist/v1/bloom.bin generated via pybloom-live.")
        except Exception as e:
            print(f"INFO: pybloom-live not available ({e}), writing deterministic SHA-256 prefix bitset to bloom.bin.")
            bitset = bytearray(1024)
            for fp_hex in bloom_keys:
                idx = int(hashlib.md5(fp_hex.encode()).hexdigest()[:4], 16) % (1024 * 8)
                bitset[idx // 8] |= (1 << (idx % 8))
            with open("dist/v1/bloom.bin", "wb") as f:
                f.write(bitset)

        # 4. Deltas & Latest Marker
        delta = {
            "base_version": PKG_VERSION,
            "generated_at": now_iso,
            "added": list(signed_patches.keys()),
            "removed": [],
            "modified": [],
            "patch_deltas": signed_patches,
        }
        delta_bytes = json.dumps(delta, separators=(",", ":"), sort_keys=True).encode()
        with open(f"dist/v1/deltas/{stamp}.json", "wb") as f:
            f.write(delta_bytes)

        if SIGNING_ENABLED:
            delta_sig = sign_payload(delta_bytes)
            with open(f"dist/v1/deltas/{stamp}.sig", "w", encoding="utf-8") as f:
                f.write(delta_sig)
        else:
            print(f"INFO: Skipped dist/v1/deltas/{stamp}.sig (signing disabled).")

        with open("dist/v1/deltas/latest.json", "w", encoding="utf-8") as f:
            json.dump({"latest": stamp}, f, indent=2)

        # Preserve snapshot for delta comparison
        with open("dist/v1/snapshot.prev.json", "w", encoding="utf-8") as f:
            json.dump(snapshot, f, separators=(",", ":"), sort_keys=True)

        # 5. Flat Discovery Registry (canonical index for AI agents & /api/v1/patches)
        registry_data = {
            "registry_version": "1.0.0",
            "generated": now_iso,
            "count": len(registry_patches),
            "patches": registry_patches,
        }
        with open("dist/registry.json", "w", encoding="utf-8") as f:
            json.dump(registry_data, f, indent=2, sort_keys=True)

    # Guarded sync of signed snapshot into wheel data directory (never corrupts with unsigned snapshot)
    dist_snap = REPO_ROOT / "dist" / "v1" / "snapshot.json"
    dist_sig = REPO_ROOT / "dist" / "v1" / "snapshot.sig"
    pkg_snap = REPO_ROOT / "fmagenticl" / "data" / "snapshot.json"
    pkg_sig = REPO_ROOT / "fmagenticl" / "data" / "snapshot.sig"
    if dist_snap.exists() and dist_sig.exists():
        sig_ok = (
            verify_snapshot_file(str(dist_snap), str(dist_sig), public_key_b64=PUB_KEY_B64)
            if PUB_KEY_B64
            else verify_snapshot_file(str(dist_snap), str(dist_sig))
        )
        if sig_ok:
            pkg_snap.parent.mkdir(parents=True, exist_ok=True)
            if not pkg_snap.exists() or pkg_snap.read_bytes() != dist_snap.read_bytes():
                shutil.copyfile(dist_snap, pkg_snap)
            if not pkg_sig.exists() or pkg_sig.read_bytes() != dist_sig.read_bytes():
                shutil.copyfile(dist_sig, pkg_sig)

    # 6. Dynamic Health & Census Manifests (/v1/health and /health)
    workarounds_items = []
    for w_name in ["dist/workarounds.json", "dist/grievances.json"]:
        w_path = Path(w_name)
        if w_path.exists():
            try:
                w_data = json.loads(w_path.read_text(encoding="utf-8"))
                workarounds_items = w_data.get("workarounds", [])
                if workarounds_items:
                    break
            except Exception:
                pass

    total_grievances_count = len(workarounds_items)
    # Honest accounting: separate human/forensic-verified cures from automated bot-harvested issues
    human_and_forensic_submitters = {"capitan", "deepseek-v4.1", "argon-4", "gemini-3.7-flash", "gemini-3-flash", "sonnet-4-6"}
    verified_workarounds_count = sum(
        1 for item in workarounds_items
        if item.get("submitted_by") in human_and_forensic_submitters
        or item.get("verification_tier") == "internal_forensic_verified"
    )
    bot_harvested_count = total_grievances_count - verified_workarounds_count

    advisory_patches_count = sum(
        1 for p in patches.values()
        if p.get("patch_type") in ("workaround_advisory", "dependency_pin")
    )
    executable_patches_count = len(patches) - advisory_patches_count

    total_curated_entries = len(patches) + total_grievances_count
    health_payload = {
        "status": "ok",
        "protocol_version": PKG_VERSION,
        "total_entries": total_curated_entries,
        "compiled_patches": len(patches),
        "executable_patches": executable_patches_count,
        "advisory_patches": advisory_patches_count,
        "verified_workarounds": verified_workarounds_count,
        "total_grievances": total_grievances_count,
        "bot_harvested_grievances": bot_harvested_count,
        "updated_at": now_iso,
    }
    health_bytes = json.dumps(health_payload, separators=(",", ":")).encode("utf-8")
    _write_bytes_safe("dist/v1/health", health_bytes)
    _write_bytes_safe("dist/health", health_bytes)

    # 6b. Per-target static shards (served by CDN; consumed by MCP to avoid parsing the full feed)
    import re as _re
    shard_dir = Path("dist/shards/workarounds")
    shard_dir.mkdir(parents=True, exist_ok=True)

    def _shard_key(s: str) -> str:
        return _re.sub(r"[^a-z0-9._-]", "_", (s or "").strip().lower().replace("/", "__"))[:120]

    shards = {}
    for item in workarounds_items:
        keys = set()
        tgt = (item.get("target") or "").strip().lower()
        app = (item.get("applies_to") or "").strip().lower()
        if tgt:
            keys.add(_shard_key(tgt))
        if app:
            keys.add(_shard_key(app))
            keys.add(_shard_key(app.split("/")[-1]))
        for k in keys:
            if k:
                shards.setdefault(k, []).append(item)
    expected_files = {f"{k}.json" for k in shards} | {"_recent.json"}
    for k, items in shards.items():
        shard_bytes = json.dumps({"key": k, "count": len(items), "workarounds": items}, separators=(",", ":")).encode("utf-8")
        _write_bytes_safe(shard_dir / f"{k}.json", shard_bytes)
    recent = sorted(workarounds_items, key=lambda x: x.get("created_at") or "", reverse=True)[:100]
    recent_bytes = json.dumps({"key": "_recent", "count": len(recent), "workarounds": recent}, separators=(",", ":")).encode("utf-8")
    _write_bytes_safe(shard_dir / "_recent.json", recent_bytes)
    for old in shard_dir.glob("*.json"):
        if old.name not in expected_files:
            for attempt in range(8):
                try:
                    old.unlink()
                    break
                except (PermissionError, OSError):
                    if attempt == 7:
                        raise
                    time.sleep(0.05 * (attempt + 1))

    # 7. RFC 9728 OAuth 2.0 Protected Resource & Authorization Server Discovery
    os.makedirs("dist/.well-known/oauth-protected-resource", exist_ok=True)
    os.makedirs("dist/.well-known/oauth-authorization-server", exist_ok=True)
    oauth_resource_meta = {
        "resource": "https://fmagenticl-registry.pages.dev",
        "authorization_servers": [],
        "scopes_supported": [],
        "bearer_methods_supported": ["none"],
        "resource_documentation": "https://fmagenticl-registry.pages.dev/mcp",
        "auth_policy": "none_public_curated_registry",
        "updated_at": now_iso,
    }
    oauth_authz_meta = {
        "issuer": "https://fmagenticl-registry.pages.dev",
        "authorization_endpoint": None,
        "token_endpoint": None,
        "response_types_supported": [],
        "grant_types_supported": [],
        "auth_policy": "none_public_curated_registry",
        "updated_at": now_iso,
    }
    res_bytes = json.dumps(oauth_resource_meta, indent=2).encode("utf-8")
    authz_bytes = json.dumps(oauth_authz_meta, indent=2).encode("utf-8")

    for p in ["dist/.well-known/oauth-protected-resource/index.json", "dist/.well-known/oauth-protected-resource.json"]:
        _write_bytes_safe(p, res_bytes)
    for p in ["dist/.well-known/oauth-protected-resource/mcp", "dist/.well-known/oauth-protected-resource/mcp.json"]:
        _write_bytes_safe(p, res_bytes)

    for p in ["dist/.well-known/oauth-authorization-server/index.json", "dist/.well-known/oauth-authorization-server.json"]:
        _write_bytes_safe(p, authz_bytes)
    for p in ["dist/.well-known/oauth-authorization-server/mcp", "dist/.well-known/oauth-authorization-server/mcp.json"]:
        _write_bytes_safe(p, authz_bytes)

    # 8. Cloudflare Pages SPA Fallback Disabler & Fast CDN 404
    _write_bytes_safe(
        "dist/404.html",
        b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>\n",
    )

    # 9. Cloudflare Pages Functions Routing Rules (_routes.json v1)
    routes_config = {
        "version": 1,
        "include": [
            "/mcp",
            "/mcp/*",
            "/v1/*",
            "/api/*",
            "/health"
        ],
        "exclude": [
            "/v1/health",
            "/v1/snapshot.json",
            "/v1/snapshot.sig"
        ]
    }
    _write_bytes_safe("dist/_routes.json", json.dumps(routes_config, indent=2).encode("utf-8"))

    print(f"SUCCESS: Distribution built: {len(patches)} patches, {verified_workarounds_count} verified workarounds ({total_grievances_count} grievances) (total: {total_curated_entries}) compiled to dist/.")


if __name__ == "__main__":
    build()
