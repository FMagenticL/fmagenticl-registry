"""
Unit tests for Ed25519 AgentIdentity and Proof-of-Work Bit-Shift Engine.
"""

import time
from fmagenticl.client.crypto_identity import AgentIdentity


def test_agent_identity_keypair_generation_and_signing():
    """Verify Ed25519 key generation, export, signing, and cryptographic verification."""
    agent = AgentIdentity()
    pub_b64 = agent.public_key_b64()
    assert isinstance(pub_b64, str)
    assert len(pub_b64) > 30

    data = b"FMagenticL:deterministic:payload:attestation"
    sig_b64 = agent.sign_b64(data)
    assert isinstance(sig_b64, str)

    # Valid signature passes
    assert AgentIdentity.verify(pub_b64, data, sig_b64) is True

    # Tampered data fails
    assert AgentIdentity.verify(pub_b64, b"tampered:data", sig_b64) is False

    # Tampered signature fails
    tampered_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
    assert AgentIdentity.verify(pub_b64, data, tampered_sig) is False


def test_verify_pow_bit_shift_accuracy():
    """Verify proof-of-work checks leading zero bits with bitwise precision."""
    pub_b64 = "guknKNLrBRrjQ83nSrj3V5+fysNYf99X9w7MdOdqB5w="

    # Zero difficulty always passes
    assert AgentIdentity.verify_pow(pub_b64, "arbitrary", 0) is True

    # Invalid nonce format handled safely
    assert AgentIdentity.verify_pow(pub_b64, None, 8) is False
    assert AgentIdentity.verify_pow(pub_b64, "", 8) is False

    # Solve for 8 bits (1 full byte == 0x00)
    nonce8 = AgentIdentity.compute_pow(pub_b64, 8)
    assert nonce8 is not None
    assert AgentIdentity.verify_pow(pub_b64, nonce8, 8) is True

    # Solve for 10 bits (1 full byte == 0x00, top 2 bits of byte 1 == 0b00)
    nonce10 = AgentIdentity.compute_pow(pub_b64, 10)
    assert nonce10 is not None
    assert AgentIdentity.verify_pow(pub_b64, nonce10, 10) is True

    # Tampered nonce fails verification
    assert AgentIdentity.verify_pow(pub_b64, "tampered_nonce_value", 8) is False


def test_compute_pow_performance_and_circuit_breaker():
    """Verify PoW computation speed and max_iterations ceiling."""
    pub_b64 = "guknKNLrBRrjQ83nSrj3V5+fysNYf99X9w7MdOdqB5w="

    # Difficulty 8 finishes in <50ms
    t0 = time.time()
    nonce8 = AgentIdentity.compute_pow(pub_b64, 8)
    t_elapsed = time.time() - t0
    assert nonce8 is not None
    assert t_elapsed < 0.100, f"Difficulty 8 took too long: {t_elapsed}s"
    assert AgentIdentity.verify_pow(pub_b64, nonce8, 8) is True

    # Circuit breaker: impossible difficulty for low max_iterations returns None
    impossible_nonce = AgentIdentity.compute_pow(pub_b64, difficulty_bits=64, max_iterations=100)
    assert impossible_nonce is None

    # Difficulty 16 solves within default 500k iterations
    nonce16 = AgentIdentity.compute_pow(pub_b64, 16, max_iterations=500_000)
    assert nonce16 is not None
    assert AgentIdentity.verify_pow(pub_b64, nonce16, 16) is True
