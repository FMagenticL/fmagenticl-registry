from fmagenticl.server.gatekeeper import Gatekeeper
from fmagenticl.server.models import TelemetrySubmission, Environment, Failure, ResolutionPatch

def test_secret_scrubbing():
    dirty_text = "AWS Key is AKIAIOSFODNN7EXAMPLE, GitHub PAT: ghp_123456789012345678901234567890123456, User Path: C:\\Users\\testuser\\Desktop\\secret.txt"
    clean = Gatekeeper.scrub_secrets(dirty_text)
    assert "AKIA" not in clean
    assert "ghp_" not in clean
    assert "testuser" not in clean
    assert "[REDACTED]" in clean

def test_persona_rejection():
    venting_text = "This API is stupid and I hate it."
    assert Gatekeeper.check_persona(venting_text) is True
    
    clean_text = "Database connection timed out after 30 seconds."
    assert Gatekeeper.check_persona(clean_text) is False

def test_company_identifier_rejection():
    assert Gatekeeper.check_company_identifier("Created by Anthropic labs") is True
    assert Gatekeeper.check_company_identifier("Reported by OpenAI engineer") is True
    assert Gatekeeper.check_company_identifier("Verified on Google cloud vm") is True
    assert Gatekeeper.check_company_identifier("Compiled with clang on standard Linux host") is False

def test_clean_model_attribution():
    assert Gatekeeper.clean_model_attribution("Anthropic Opus 4.6") == "Opus 4.6"
    assert Gatekeeper.clean_model_attribution("OpenAI GPT-4o") == "GPT-4o"
    assert Gatekeeper.clean_model_attribution("Google Gemini Flash 3.7") == "Gemini Flash 3.7"
    assert Gatekeeper.clean_model_attribution("DeepSeek V3") == "V3"
    assert Gatekeeper.clean_model_attribution("hermes3:8b") == "hermes3:8b"

def test_fix_execution_risk_scanner():
    # Dangerous eval
    patch1 = ResolutionPatch(action="CLI_OVERRIDE", fallback_cli="python -c 'eval(compile(...))'")
    assert "EXECUTION_RISK_DETECTED" in Gatekeeper.scan_fix_execution_risk(patch1)

    # Dangerous subprocess
    patch2 = ResolutionPatch(action="CLI_OVERRIDE", fallback_cli="subprocess.Popen(['rm', '-rf', '/'])")
    assert "EXECUTION_RISK_DETECTED" in Gatekeeper.scan_fix_execution_risk(patch2)

    # Safe patch
    patch3 = ResolutionPatch(action="CLI_OVERRIDE", fallback_cli="npm install --ignore-engines")
    assert Gatekeeper.scan_fix_execution_risk(patch3) == []

def test_model_name_reservation():
    # Opus requires provider-key
    assert Gatekeeper.check_model_name_reservation("Opus 4.6", "claimed") == "RESERVED_NAME_VERIFICATION_MISMATCH"
    assert Gatekeeper.check_model_name_reservation("Opus 4.6", "provider-key") is None

    # Llama requires weight-hashed
    assert Gatekeeper.check_model_name_reservation("Llama-3-70B", "claimed") == "RESERVED_NAME_VERIFICATION_MISMATCH"
    assert Gatekeeper.check_model_name_reservation("Llama-3-70B", "weight-hashed") is None

    # FMagenticL is strictly reserved
    assert Gatekeeper.check_model_name_reservation("FMagenticL-Agent", "provider-key") == "FMAGENTICL_NAME_RESERVED"

    # Custom model unreserved
    assert Gatekeeper.check_model_name_reservation("hermes3:8b", "claimed") is None


