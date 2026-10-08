"""
Unit tests for FMagenticLClient submission and grievance methods:
- report_failure
- submit_grievance
- get_grievances
and their integration with fastmcp_server tools.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
import httpx

from fmagenticl.client.middleware import FMagenticLClient
from fmagenticl.client import fastmcp_server


@pytest.fixture
def client():
    return FMagenticLClient(edge_base="http://testserver")


# ===========================================================================
# 1. report_failure
# ===========================================================================

def test_report_failure_success(client):
    env = {"os": "win32", "os_version": "10.0.26100"}
    fail = {"error_code": "EBADENGINE", "exit_code": 1}
    patch_obj = {"op": "remove", "path": "/engines"}

    mock_resp = MagicMock()
    mock_resp.status_code = 202
    mock_resp.json.return_value = {"status": "ACCEPTED", "fingerprint": "sha256:test"}

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        res = client.report_failure(
            environment=env,
            failure=fail,
            resolution_patch=patch_obj,
            verified=True,
            technical_note="Verified fix"
        )
        assert res["status"] == "ACCEPTED"
        assert mock_post.called
        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == "http://testserver/v1/telemetry"
        sent_json = call_kwargs["json"]
        assert sent_json["environment"] == env
        assert sent_json["failure"] == fail
        assert sent_json["resolution_patch"] == patch_obj
        assert sent_json["verified_by_reporter"] is True
        assert sent_json["technical_note"] == "Verified fix"
        assert sent_json["fingerprint"].startswith("sha256:")


def test_report_failure_network_error_never_raises(client):
    env = {"os": "win32"}
    fail = {"error_code": "FAIL"}
    patch_obj = {}

    with patch("httpx.post", side_effect=httpx.ConnectTimeout("Connection timed out")):
        res = client.report_failure(environment=env, failure=fail, resolution_patch=patch_obj)
        assert res["status"] == "NETWORK_ERROR"
        assert "timed out" in res["error"]


def test_report_failure_http_error(client):
    env = {"os": "win32"}
    fail = {"error_code": "FAIL"}
    patch_obj = {}

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("httpx.post", return_value=mock_resp):
        res = client.report_failure(environment=env, failure=fail, resolution_patch=patch_obj)
        assert res["status"] == "FAILED"
        assert res["status_code"] == 500


# ===========================================================================
# 2. submit_grievance
# ===========================================================================

def test_submit_grievance_success(client):
    env = {"os": "win32", "runtime": "node@24"}
    mock_resp = MagicMock()
    mock_resp.status_code = 202
    mock_resp.json.return_value = {"status": "ACCEPTED", "id": "grv_12345"}

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        res = client.submit_grievance(
            grievance_type="INFRASTRUCTURE_FRICTION",
            target="projected_fs",
            environment=env,
            symptom="Directory walk locks file handle indefinitely.",
            workaround="Use flat FindFirstFileW scan instead of recursive walk.",
            harness="antigravity",
            submitted_by="operator"
        )
        assert res["status"] == "ACCEPTED"
        assert mock_post.called
        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["grievance_type"] == "INFRASTRUCTURE_FRICTION"
        assert sent_json["target"] == "projected_fs"
        assert sent_json["workaround"] == "Use flat FindFirstFileW scan instead of recursive walk."
        assert sent_json["submitted_by"] == "operator"


def test_submit_grievance_rejects_short_workaround(client):
    env = {"os": "linux"}
    res = client.submit_grievance(
        grievance_type="INFRASTRUCTURE_FRICTION",
        target="some_target",
        environment=env,
        symptom="Broken",
        workaround="fix"  # < 5 chars
    )
    assert res["status"] == "REJECTED"
    assert res["error"] == "workaround_missing_or_too_short"


def test_submit_grievance_rejects_invalid_type(client):
    env = {"os": "linux"}
    res = client.submit_grievance(
        grievance_type="INVALID_COMPLAINT_TYPE",
        target="some_target",
        environment=env,
        symptom="Broken",
        workaround="Valid workaround with more than 5 characters"
    )
    assert res["status"] == "REJECTED"
    assert res["error"] == "invalid_grievance_type"


def test_submit_grievance_default_anonymous(client):
    env = {"os": "linux"}
    mock_resp = MagicMock()
    mock_resp.status_code = 202
    mock_resp.json.return_value = {"status": "ACCEPTED"}

    with patch("httpx.post", return_value=mock_resp) as mock_post:
        client.submit_grievance(
            grievance_type="PROTOCOL_FRICTION",
            target="tool_parser",
            environment=env,
            symptom="Unescaped unicode crashes deserializer",
            workaround="Sanitize unicode surrogates before parse"
        )
        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["submitted_by"] == "anonymous"


# ===========================================================================
# 3. get_grievances
# ===========================================================================

def test_get_grievances_success(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "target": "google_drive_fs",
        "total": 1,
        "grievances": [{"id": "grv_1", "workaround": "Use flat listdir"}]
    }

    with patch("httpx.get", return_value=mock_resp) as mock_get:
        res = client.get_grievances("google_drive_fs")
        assert res["total"] == 1
        assert len(res["grievances"]) == 1
        assert mock_get.called
        assert mock_get.call_args[0][0] == "http://testserver/v1/grievance/google_drive_fs"


def test_get_grievances_error_returns_empty_structure(client):
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.get", return_value=mock_resp):
        res = client.get_grievances("unknown_target")
        assert res["target"] == "unknown_target"
        assert res["total"] == 0
        assert res["grievances"] == []


def test_get_grievances_network_exception_never_raises(client):
    with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        res = client.get_grievances("offline_target")
        assert res["target"] == "offline_target"
        assert res["total"] == 0
        assert res["grievances"] == []


# ===========================================================================
# 4. FastMCP Tooling Integration
# ===========================================================================

def test_fastmcp_report_integration():
    env = {"os": "win32"}
    fail = {"error_code": "ERR"}
    patch_obj = {"action": "PATCH"}

    with patch.object(fastmcp_server.client, "report_failure", return_value={"status": "ACCEPTED"}) as mock_m:
        res = fastmcp_server._report(env, fail, patch_obj)
        assert res["status"] == "QUEUED_FOR_SYNC"
        assert mock_m.called


def test_fastmcp_submit_grievance_integration():
    env = {"os": "win32"}
    with patch.object(fastmcp_server.client, "submit_grievance", return_value={"status": "ACCEPTED", "id": "grv_1"}) as mock_m:
        res = fastmcp_server._submit_grievance(
            grievance_type="INFRASTRUCTURE_FRICTION",
            target="target1",
            environment=env,
            symptom="symptom description",
            workaround="workaround text"
        )
        assert res["status"] == "ACCEPTED"
        assert mock_m.called


def test_fastmcp_get_grievances_integration():
    with patch.object(fastmcp_server.client, "get_grievances", return_value={"target": "target1", "total": 0, "grievances": []}) as mock_m:
        res = fastmcp_server._get_grievances("target1")
        assert res["target"] == "target1"
        assert mock_m.called
