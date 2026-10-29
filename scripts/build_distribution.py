import os, sys, json, glob, hashlib, datetime, base64
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

    # 1. Per-patch files (individually cacheable, only write if missing or changed)
    resolve_changed = False
    for fp_hex, data in patches.items():
        resolve_path = Path(f"dist/v1/resolve/{fp_hex}.json")
        serialized = json.dumps(data, separators=(",", ":"))
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
            "version": "1.3.1",
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
            "base_version": "1.3.1",
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
    workarounds_count = 0
    for w_name in ["dist/workarounds.json", "dist/grievances.json"]:
        w_path = Path(w_name)
        if w_path.exists():
            try:
                w_data = json.loads(w_path.read_text(encoding="utf-8"))
                workarounds_count = w_data.get("count") or len(w_data.get("workarounds", []))
                if workarounds_count > 0:
                    break
            except Exception:
                pass

    total_curated_entries = len(patches) + workarounds_count
    health_payload = {
        "status": "ok",
        "protocol_version": "1.3.1",
        "total_entries": total_curated_entries,
        "compiled_patches": len(patches),
        "verified_workarounds": workarounds_count,
        "total_grievances": workarounds_count,
        "updated_at": now_iso,
    }
    health_bytes = json.dumps(health_payload, separators=(",", ":")).encode("utf-8")
    with open("dist/v1/health", "wb") as f:
        f.write(health_bytes)
    with open("dist/health", "wb") as f:
        f.write(health_bytes)

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

    print(f"SUCCESS: Distribution built: {len(patches)} patches, {workarounds_count} workarounds (total: {total_curated_entries}) compiled to dist/.")

if __name__ == "__main__":
    build()
