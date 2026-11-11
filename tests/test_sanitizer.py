"""
Tests for Client-Side Secret and PII Sanitizer Engine.
Verifies that all API keys, JWTs, DB URIs, and user paths are scrubbed before transmission.
"""

from unittest.mock import patch
import json
from fmagenticl.client.sanitizer import scrub_text, scrub_structure
from fmagenticl.client.middleware import FMagenticLClient


def test_scrub_aws_keys():
    raw = "Error occurred with AWS key AKIA" + "IOSFODNN7EXAMPLE and secret aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    clean = scrub_text(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "[REDACTED_AWS_KEY]" in clean
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in clean
    assert "aws_secret_access_key=[REDACTED]" in clean


def test_scrub_github_and_openai_tokens():
    raw = "Failed pushing with ghp_" + ("1234567890" * 4) + " and sk-proj-" + ("1234567890" * 3)
    clean = scrub_text(raw)
    assert "ghp_" not in clean
    assert "[REDACTED_GITHUB_TOKEN]" in clean
    assert "sk-proj-" not in clean
    assert "[REDACTED_OPENAI_KEY]" in clean


def test_scrub_database_uris():
    raw = "Failed connection to postgres://app_user:SuperSecretP@ss@db.internal.corp:5432/production"
    clean = scrub_text(raw)
    assert "SuperSecretP@ss" not in clean
    assert "[REDACTED_DB_URI]" in clean


def test_scrub_user_home_paths():
    win_path = r"FileNotFoundError: [Errno 2] No such file or directory: 'C:\Users\itari\Desktop\secret.key'"
    linux_path = "Traceback (most recent call last): File \"/home/deployer/app/main.py\", line 12"
    mac_path = "Exception in /Users/charlie/Documents/repo/config.json"

    assert "<USER_HOME>" in scrub_text(win_path)
    assert "itari" not in scrub_text(win_path)
    assert "<USER_HOME>" in scrub_text(linux_path)
    assert "deployer" not in scrub_text(linux_path)
    assert "<USER_HOME>" in scrub_text(mac_path)
    assert "charlie" not in scrub_text(mac_path)


def test_scrub_nested_structure():
    jwt_mock = "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mock_signature_part"
    payload = {
        "failure": {
            "error_code": "DB_AUTH_FAILED",
            "message": "Access denied for user 'admin' using password 'Hunter2!' at postgres://admin:Hunter2!@10.0.0.1/db",
            "stacktrace": [
                "File C:\\Users\\developer\\app.py, line 42, in connect",
                "Auth" + "orization: Bear" + f"er {jwt_mock}"
            ]
        },
        "env": {"user": "developer"}
    }
    clean = scrub_structure(payload)
    assert "Hunter2!" not in clean["failure"]["message"]
    assert "[REDACTED_DB_URI]" in clean["failure"]["message"]
    assert "developer" not in clean["failure"]["stacktrace"][0]
    assert "<USER_HOME>" in clean["failure"]["stacktrace"][0]
    assert "[REDACTED_BEARER_TOKEN]" in clean["failure"]["stacktrace"][1]


def test_report_failure_outbound_payload_redaction():
    """Verify that report_failure scrubs raw JWTs, AWS keys, and DB URIs before network dispatch."""
    client = FMagenticLClient()

    jwt_token = "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    db_uri = "postgres://superadmin:TopSecretPassword123@db.prod.internal:5432/secrets_db"

    env = {"runtime": "python@3.12", "aws_key": aws_key}
    failure = {
        "error": f"Failed connecting to {db_uri}",
        "auth_header": "Bearer " + jwt_token,
        "traceback": [
            r"File C:\Users\developer\secrets\app.py, line 99",
            f"database_url = '{db_uri}'"
        ]
    }
    patch_dict = {"patch_type": "advisory", "text": "Fix credentials"}

    with patch("httpx.post") as mock_post:
        mock_post.return_value.status_code = 202
        mock_post.return_value.json.return_value = {"status": "ACCEPTED"}

        client.report_failure(
            environment=env,
            failure=failure,
            resolution_patch=patch_dict,
            technical_note=f"Secret was leaked with token {jwt_token}"
        )

        assert mock_post.called
        sent_payload = mock_post.call_args[1]["json"]

        payload_str = json.dumps(sent_payload)

        assert aws_key not in payload_str
        assert "[REDACTED_AWS_KEY]" in payload_str

        assert "TopSecretPassword123" not in payload_str
        assert "[REDACTED_DB_URI]" in payload_str

        assert jwt_token not in payload_str
        assert "[REDACTED_BEARER_TOKEN]" in payload_str or "[REDACTED_JWT]" in payload_str

        assert "developer" not in payload_str
        assert "<USER_HOME>" in payload_str


def test_scrub_dict_keys_with_bare_passwords():
    obj = {
        "password": "BareSecretWithoutPrefix123!",
        "passwd": "AnotherPassword456",
        "api_key": "987654321",
        "token": "secret_token_val",
        "auth_header": "CustomToken XYZ",
        "safe_field": "Normal value"
    }
    scrubbed = scrub_structure(obj)
    assert scrubbed["password"] == "[REDACTED]"
    assert scrubbed["passwd"] == "[REDACTED]"
    assert scrubbed["api_key"] == "[REDACTED]"
    assert scrubbed["token"] == "[REDACTED]"
    assert scrubbed["auth_header"] == "[REDACTED]"
    assert scrubbed["safe_field"] == "Normal value"


def test_scrub_root_posix_paths():
    raw = "Error in /root/deployment/agent.py at line 42"
    clean = scrub_text(raw)
    assert "/root/deployment" not in clean
    assert "<USER_HOME>/agent.py" in clean


def test_submit_grievance_and_outcome_outbound_redaction():
    client = FMagenticLClient()
    jwt_token = "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    db_uri = "postgres://superadmin:TopSecretPassword123@db.prod.internal:5432/secrets_db"

    with patch("httpx.post") as mock_post:
        mock_post.return_value.status_code = 202
        mock_post.return_value.json.return_value = {"status": "ACCEPTED"}

        client.submit_grievance(
            grievance_type="INFRASTRUCTURE_FRICTION",
            target="docker",
            environment={"root_path": "/root/agent/secrets"},
            symptom=f"Failed connection {db_uri}",
            workaround=f"Use token {jwt_token}",
        )
        assert mock_post.called
        sent_grievance = mock_post.call_args[1]["json"]
        grievance_str = json.dumps(sent_grievance)
        assert "TopSecretPassword123" not in grievance_str
        assert "[REDACTED_DB_URI]" in grievance_str
        assert "/root/agent" not in grievance_str
        assert "<USER_HOME>" in grievance_str

    with patch("httpx.post") as mock_post:
        mock_post.return_value.status_code = 202
        mock_post.return_value.json.return_value = {"status": "ACCEPTED"}

        client.report_patch_outcome(
            fingerprint="sha256:abc123",
            outcome="ACK",
            submitted_by="engineer",
            notes=f"Applied with secret db {db_uri}"
        )
        assert mock_post.called
        sent_outcome = mock_post.call_args[1]["json"]
        outcome_str = json.dumps(sent_outcome)
        assert "TopSecretPassword123" not in outcome_str
        assert "[REDACTED_DB_URI]" in outcome_str


def test_fastmcp_auto_heal_scrubs_inbound():
    from fmagenticl.client.fastmcp_server import _auto_heal, client
    env = {"path": "/root/sensitive/path", "password": "supersecretpassword"}
    failure = {"error": "Connection error to postgres://admin:pass123@host:5432/db"}
    ctx = {"local_dir": r"C:\Users\admin\repo"}

    with patch.object(client, "resolve_failure") as mock_resolve:
        mock_resolve.return_value = None
        res = _auto_heal(env, failure, ctx)
        assert res is not None
        assert mock_resolve.called
        called_env, called_fail = mock_resolve.call_args[0][:2]
        called_ctx = mock_resolve.call_args[1].get("context", {})
        assert called_env["password"] == "[REDACTED]"
        assert "<USER_HOME>" in called_env["path"]
        assert "[REDACTED_DB_URI]" in called_fail["error"]
        assert "<USER_HOME>" in called_ctx["local_dir"]
