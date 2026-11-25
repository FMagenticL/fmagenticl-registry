"""F2 completeness (2026-11-25) — EVERY egress path must honour air-gap, not just resolve().

The first F2 patch guarded only the resolve path. The in-build Goldfish audit then found four more
methods reaching `self.edge_base` directly via `httpx`, bypassing the guard entirely. This file
enumerates the egress surface so the guarantee cannot silently regress when a sixth method is added.

Two contracts are asserted separately, because they are deliberately different:
  * the resolve path RAISES (the caller asked for an answer);
  * report_*/get_* RETURN a REFUSED_AIR_GAP status dict (they promise never to raise).
Both must make zero socket calls.
"""

import socket

import pytest

from fmagenticl.client.errors import FMagenticLIntegrityError
from fmagenticl.client.local_cache import LocalCache
from fmagenticl.client.middleware import FMagenticLClient


def _guarded_client(tmp_path, monkeypatch, **kwargs):
    """A client whose bundled snapshot is present but fails verification."""
    monkeypatch.setattr(
        "fmagenticl.client.local_cache.verify_snapshot_file", lambda *a, **k: False
    )
    cache = LocalCache(delta_path=str(tmp_path / "delta.json"))
    assert cache._snapshot_verification_failed is True, "verification failure must be recorded"
    return FMagenticLClient(local_cache=cache, require_signature=True, **kwargs)


def _forbid_sockets(monkeypatch):
    calls = []

    def _forbid(*args, **kwargs):
        calls.append(1)
        raise AssertionError("network egress attempted")

    monkeypatch.setattr(socket.socket, "connect", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)
    return calls


# The complete egress surface of FMagenticLClient, as measured by grepping every `httpx.` call in
# middleware.py. If a new egress method is added, add it here -- the parametrised test below is what
# makes "air-gap is honoured" a checkable claim rather than an intention.
EGRESS_CALLS = [
    ("report_failure", lambda c: c.report_failure(
        environment={}, failure={}, resolution_patch={})),
    ("report_telemetry", lambda c: c.report_telemetry(
        environment={}, failure={}, resolution_patch={})),
    ("submit_grievance", lambda c: c.submit_grievance(
        grievance_type="AGENT_FRICTION", target="requests", environment={},
        symptom="pool exhaustion under load",
        workaround="Upgrade requests to 2.31.0 to clear the pool exhaustion defect.")),
    ("get_grievances", lambda c: c.get_grievances("requests")),
    ("get_workarounds", lambda c: c.get_workarounds("requests")),
    ("report_patch_outcome", lambda c: c.report_patch_outcome(
        fingerprint="a" * 64, outcome="ACK", submitted_by="test-model")),
]


@pytest.mark.parametrize("name,call", EGRESS_CALLS, ids=[n for n, _ in EGRESS_CALLS])
def test_every_egress_method_refuses_in_air_gap(tmp_path, monkeypatch, name, call):
    """Air-gap ON: no egress method may open a socket; each reports REFUSED_AIR_GAP."""
    calls = _forbid_sockets(monkeypatch)
    client = _guarded_client(tmp_path, monkeypatch, air_gap=True)

    result = call(client)

    assert calls == [], f"{name} attempted network egress in air-gap mode"
    assert isinstance(result, dict), f"{name} must keep returning a status dict"
    assert result.get("status") == "REFUSED_AIR_GAP", f"{name} -> {result!r}"


def test_resolve_path_raises_rather_than_egress(tmp_path, monkeypatch):
    """The resolve path is the one place that raises, so the caller cannot miss it."""
    calls = _forbid_sockets(monkeypatch)
    client = _guarded_client(tmp_path, monkeypatch, air_gap=True)

    with pytest.raises(FMagenticLIntegrityError):
        client.resolve("0" * 64)

    assert calls == []


@pytest.mark.parametrize("name,call", EGRESS_CALLS, ids=[n for n, _ in EGRESS_CALLS])
def test_air_gap_off_restores_egress_for_every_method(tmp_path, monkeypatch, name, call):
    """Positive control: the guard is what blocks egress, not an unrelated early return.

    Parametrized per method so every single egress call is proven to reach socket egress
    when air_gap=False.
    """
    calls = _forbid_sockets(monkeypatch)
    client = _guarded_client(tmp_path, monkeypatch, air_gap=False)

    try:
        call(client)
    except Exception:
        pass  # the socket hook firing is the expected signal

    assert calls, f"control: with air_gap=False {name} must attempt egress"


def test_ast_all_httpx_calls_in_middleware_are_enumerated():
    """AST completeness check: every httpx.* call in FMagenticLClient is covered by EGRESS_CALLS or resolve."""
    import ast
    from pathlib import Path

    mw_path = Path(__file__).resolve().parent.parent / "fmagenticl" / "client" / "middleware.py"
    tree = ast.parse(mw_path.read_text(encoding="utf-8"))

    httpx_methods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "FMagenticLClient":
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    for sub in ast.walk(item):
                        if (
                            isinstance(sub, ast.Attribute)
                            and isinstance(sub.value, ast.Name)
                            and sub.value.id == "httpx"
                        ):
                            httpx_methods.add(item.name)

    covered = {name for name, _ in EGRESS_CALLS} | {"_query_remote_unchecked"}
    missing = httpx_methods - covered
    assert not missing, f"Uncovered httpx methods in FMagenticLClient: {sorted(missing)}"
