import base64
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fmagenticl.client.verify import canonical_json_bytes


def test_e2e_self_healing_flow(monkeypatch, tmp_path):
    captured_urls = []

    # Generate an ephemeral test keypair for authentic signing
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_bytes).decode()

    def fake_get(url, **kwargs):
        captured_urls.append(url)
        response = MagicMock()
        if "/v1/resolve/" in url and url.endswith(".json"):
            fp = url.rsplit("/", 1)[-1].replace(".json", "")
            patch_data = {
                "fingerprint": f"sha256:{fp}",
                "patch_type": "application/json-patch+json",
                "json_patch": [{"op": "remove", "path": "/engines"}],
                "confidence": 0.98,
                "submitted_by": "test",
                "verification_tier": "claimed",
                "foundational": False,
            }
            # Sign canonically
            sig_b64 = base64.b64encode(priv.sign(canonical_json_bytes(patch_data))).decode()
            patch_data["ed25519_sig"] = sig_b64
            response.status_code = 200
            response.json.return_value = patch_data
        else:
            response.status_code = 404
            response.json.return_value = {"detail": "Not Found"}
        return response

    monkeypatch.setattr("fmagenticl.client.middleware.httpx.get", fake_get)
    monkeypatch.setenv("FMAGENTICL_DELTA_CACHE_PATH", str(tmp_path / "delta.json"))

    from fmagenticl.client.local_cache import LocalCache
    from fmagenticl.client.middleware import MiddlewareClient

    cache = LocalCache(snapshot_path="/nonexistent/snapshot.json", public_key_b64=pub_b64)
    client = MiddlewareClient(local_cache=cache, require_signature=True)

    result = client.resolve("49f800ca559979a58e778451778b318026853c0c37814f1880b64047db68fae6")

    assert result is not None, f"resolve returned None. URLs attempted: {captured_urls}"
    assert result["patch_type"] == "application/json-patch+json"
    assert result["json_patch"] == [{"op": "remove", "path": "/engines"}]
    assert result["signature_verified"] is True
    assert any(url.endswith(".json") for url in captured_urls), (
        f"Client did not request .json-suffixed URL. Attempted: {captured_urls}"
    )
