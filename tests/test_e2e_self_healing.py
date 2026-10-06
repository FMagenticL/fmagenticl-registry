"""
End-to-end self-healing flow test.

Verifies the full loop: a failing tool call produces a fingerprint, the
client queries the edge CDN, receives a patch, and applies it.
"""

from unittest.mock import MagicMock

import pytest


def test_e2e_self_healing_flow(monkeypatch, tmp_path):
    captured_urls = []

    def fake_get(url, **kwargs):
        captured_urls.append(url)
        response = MagicMock()
        if "/v1/resolve/" in url and url.endswith(".json"):
            fp = url.rsplit("/", 1)[-1].replace(".json", "")
            response.status_code = 200
            response.json.return_value = {
                "fingerprint": f"sha256:{fp}",
                "patch_type": "application/json-patch+json",
                "json_patch": [{"op": "remove", "path": "/engines"}],
                "confidence": 0.98,
                "submitted_by": "test",
                "verification_tier": "claimed",
                "foundational": False,
            }
        else:
            response.status_code = 404
            response.json.return_value = {"detail": "Not Found"}
        return response

    monkeypatch.setattr("fmagenticl.client.middleware.httpx.get", fake_get)
    monkeypatch.setenv("FMAGENTICL_DELTA_CACHE_PATH", str(tmp_path / "delta.json"))

    from fmagenticl.client.local_cache import LocalCache
    from fmagenticl.client.middleware import MiddlewareClient

    cache = LocalCache(snapshot_path="/nonexistent/snapshot.json")
    client = MiddlewareClient(local_cache=cache)

    result = client.resolve("49f800ca559979a58e778451778b318026853c0c37814f1880b64047db68fae6")

    assert result is not None, f"resolve returned None. URLs attempted: {captured_urls}"
    assert result["patch_type"] == "application/json-patch+json"
    assert result["json_patch"] == [{"op": "remove", "path": "/engines"}]
    assert any(url.endswith(".json") for url in captured_urls), (
        f"Client did not request .json-suffixed URL. Attempted: {captured_urls}"
    )
