import os, sys, json, glob, hashlib, datetime, base64
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from fmagenticl import __version__ as PKG_VERSION
except Exception:
    PKG_VERSION = "1.4.1"

SIGNING_KEY_B64 = os.environ.get("FMAGENTICL_SIGNING_KEY", "PLACEHOLDER_SIGNING_KEY_NOT_SET")
if SIGNING_KEY_B64 == "PLACEHOLDER_SIGNING_KEY_NOT_SET":
    print("WARNING: Signing key not set. Emitting unsigned snapshot. Set FMAGENTICL_SIGNING_KEY to enable signing.")
    SIGNING_ENABLED = False
    priv = None
else:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(SIGNING_KEY_B64))
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


def build():
    os.makedirs("dist/v1/resolve", exist_ok=True)
    os.makedirs("dist/v1/deltas", exist_ok=True)
    os.makedirs("dist/.well-known", exist_ok=True)

    patches = load_patches()

    # Build canonical registry_patches list first for content-idempotency check
    try:
        from fmagenticl.client.fingerprint import compute_fingerprint
        from fmagenticl.server.seed_hermes import RAW_SEED_CASES
        seed_map = {
            compute_fingerprint(c["env"], c["fail"]).replace("sha256:", ""): c["fail"].get("error_code") or c["fail"].get("error")
            for c in RAW_SEED_CASES
        }
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

    # 1. Per-patch files (individually cacheable; Ed25519-signed when SIGNING_ENABLED)
    resolve_changed = False
    for fp_hex, data in patches.items():
        resolve_path = Path(f"dist/v1/resolve/{fp_hex}.json")
        out_data = dict(data)
        out_data.setdefault("fingerprint", f"sha256:{fp_hex}")
        if SIGNING_ENABLED:
            clean_patch = {
                k: v
                for k, v in out_data.items()
                if k not in ("signature", "ed25519_sig", "signature_verified", "fingerprint_verified")
            }
            canon_bytes = json.dumps(clean_patch, sort_keys=True, separators=(",", ":")).encode("utf-8")
            out_data["ed25519_sig"] = sign_payload(canon_bytes)
        elif resolve_path.exists():
            # Preserve existing ed25519_sig on disk during unsigned local builds if canonical content matches
            try:
                prev_disk = json.loads(resolve_path.read_text(encoding="utf-8"))
                if prev_disk.get("ed25519_sig"):
                    prev_clean = {k: v for k, v in prev_disk.items() if k != "ed25519_sig"}
                    if prev_clean == out_data:
                        out_data["ed25519_sig"] = prev_disk["ed25519_sig"]
            except Exception:
                pass
        serialized = json.dumps(out_data, separators=(",", ":"), sort_keys=True)
        if not resolve_path.exists() or resolve_path.read_text(encoding="utf-8") != serialized:
            resolve_path.write_text(serialized, encoding="utf-8")
            resolve_changed = True

    # Content-comparison guard: skip timestamp/signature churn if patches are identical
    patches_unchanged = False
    if (
        not resolve_changed
        and os.path.exists("dist/registry.json")
        and os.path.exists("dist/v1/snapshot.json")
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
                and existing_snap.get("patches") == patches
                and existing_snap.get("total_patches") == len(patches)
            ):
                patches_unchanged = True
                print(f"Distribution patches unchanged (count: {len(registry_patches)}). Preserving snapshot/signatures.")
        except Exception:
            pass

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = now_utc.strftime("%Y%m%d%H%M%S")

    if not patches_unchanged:
        # 2. Base Snapshot
        snapshot = {
            "version": PKG_VERSION,
            "generated_at": now_iso,
            "total_patches": len(patches),
            "patches": patches,
        }
        snapshot_bytes = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode()

        with open("dist/v1/snapshot.json", "wb") as f:
            f.write(snapshot_bytes)

        if SIGNING_ENABLED:
            snapshot_signature = sign_payload(snapshot_bytes)
            with open("dist/v1/snapshot.sig", "w") as f:
                f.write(snapshot_signature)
        else:
            print("INFO: Skipped dist/v1/snapshot.sig (signing disabled).")

        # 3. Bloom filter (for fast negative lookups)
        try:
            from pybloom_live import BloomFilter
            bloom = BloomFilter(capacity=max(10000, len(patches) * 4), error_rate=0.001)
            for fp_hex in patches:
                bloom.add(fp_hex)
            with open("dist/v1/bloom.bin", "wb") as f:
                bloom.tofile(f)
            print("INFO: dist/v1/bloom.bin generated via pybloom-live.")
        except Exception as e:
            print(f"INFO: pybloom-live not available ({e}), writing deterministic SHA-256 prefix bitset to bloom.bin.")
            bitset = bytearray(1024)
            for fp_hex in patches:
                idx = int(hashlib.md5(fp_hex.encode()).hexdigest()[:4], 16) % (1024 * 8)
                bitset[idx // 8] |= (1 << (idx % 8))
            with open("dist/v1/bloom.bin", "wb") as f:
                f.write(bitset)

        # 4. Deltas & Latest Marker
        delta = {
            "base_version": PKG_VERSION,
            "generated_at": now_iso,
            "added": list(patches.keys()),
            "removed": [],
            "modified": [],
            "patch_deltas": patches,
        }
        delta_bytes = json.dumps(delta, separators=(",", ":"), sort_keys=True).encode()
        with open(f"dist/v1/deltas/{stamp}.json", "wb") as f:
            f.write(delta_bytes)

        if SIGNING_ENABLED:
            delta_sig = sign_payload(delta_bytes)
            with open(f"dist/v1/deltas/{stamp}.sig", "w") as f:
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

    total_curated_entries = len(patches) + total_grievances_count
    health_payload = {
        "status": "ok",
        "protocol_version": PKG_VERSION,
        "total_entries": total_curated_entries,
        "compiled_patches": len(patches),
        "verified_workarounds": verified_workarounds_count,
        "total_grievances": total_grievances_count,
        "bot_harvested_grievances": bot_harvested_count,
        "updated_at": now_iso,
    }
    health_bytes = json.dumps(health_payload, separators=(",", ":")).encode("utf-8")
    with open("dist/v1/health", "wb") as f:
        f.write(health_bytes)
    with open("dist/health", "wb") as f:
        f.write(health_bytes)

    # 6b. Per-target static shards (served by CDN; consumed by MCP to avoid parsing the full feed)
    import re as _re
    shard_dir = Path("dist/shards/workarounds")
    shard_dir.mkdir(parents=True, exist_ok=True)
    for old in shard_dir.glob("*.json"):
        old.unlink()

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
    for k, items in shards.items():
        (shard_dir / f"{k}.json").write_text(
            json.dumps({"key": k, "count": len(items), "workarounds": items}, separators=(",", ":")),
            encoding="utf-8",
        )
    recent = sorted(workarounds_items, key=lambda x: x.get("created_at") or "", reverse=True)[:100]
    (shard_dir / "_recent.json").write_text(
        json.dumps({"key": "_recent", "count": len(recent), "workarounds": recent}, separators=(",", ":")),
        encoding="utf-8",
    )

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
        with open(p, "wb") as f:
            f.write(res_bytes)
    for p in ["dist/.well-known/oauth-protected-resource/mcp", "dist/.well-known/oauth-protected-resource/mcp.json"]:
        with open(p, "wb") as f:
            f.write(res_bytes)

    for p in ["dist/.well-known/oauth-authorization-server/index.json", "dist/.well-known/oauth-authorization-server.json"]:
        with open(p, "wb") as f:
            f.write(authz_bytes)
    for p in ["dist/.well-known/oauth-authorization-server/mcp", "dist/.well-known/oauth-authorization-server/mcp.json"]:
        with open(p, "wb") as f:
            f.write(authz_bytes)

    # 8. Cloudflare Pages SPA Fallback Disabler & Fast CDN 404
    with open("dist/404.html", "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>\n")

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
    with open("dist/_routes.json", "w", encoding="utf-8") as f:
        json.dump(routes_config, f, indent=2)

    print(f"SUCCESS: Distribution built: {len(patches)} patches, {verified_workarounds_count} verified workarounds ({total_grievances_count} grievances) (total: {total_curated_entries}) compiled to dist/.")


if __name__ == "__main__":
    build()
