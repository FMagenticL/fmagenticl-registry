"""
Tests for Client-Side Secret and PII Sanitizer Engine.
Verifies that all API keys, JWTs, DB URIs, and user paths are scrubbed before transmission.
"""

from fmagenticl.client.sanitizer import scrub_text, scrub_structure


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
