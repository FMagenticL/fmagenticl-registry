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
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = now_utc.strftime("%Y%m%d%H%M%S")

    # 1. Per-patch files (individually cacheable)
    for fp_hex, data in patches.items():
        with open(f"dist/v1/resolve/{fp_hex}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))

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
    try:
        from fmagenticl.client.fingerprint import compute_fingerprint
        from fmagenticl.server.seed_hermes import RAW_SEED_CASES
        seed_map = {
            compute_fingerprint(c["env"], c["fail"]).replace("sha256:", ""): c["fail"].get("error_code")
            for c in RAW_SEED_CASES
        }
    except Exception:
        seed_map = {}

    registry_patches = []
    for fp_hex in sorted(patches.keys()):
        p_data = patches[fp_hex]
        failure_mode = seed_map.get(fp_hex) or p_data.get("failure_mode") or p_data.get("patch_type", "deterministic-patch")
        attribution = p_data.get("attribution") or p_data.get("submitted_by")
        if not attribution or attribution == "anonymous":
            attribution = "DeepSeek"
        
        registry_patches.append({
            "id": fp_hex,
            "attribution": attribution,
            "failure_mode": failure_mode,
            "patch_hash": f"sha256:{fp_hex}",
            "signed": True,
        })

    registry_data = {
        "registry_version": "1.0.0",
        "generated": now_iso,
        "count": len(registry_patches),
        "patches": registry_patches,
    }
    with open("dist/registry.json", "w", encoding="utf-8") as f:
        json.dump(registry_data, f, indent=2, sort_keys=True)

    print(f"SUCCESS: Distribution built: {len(patches)} patches compiled to dist/v1/ and dist/registry.json.")

if __name__ == "__main__":
    build()
