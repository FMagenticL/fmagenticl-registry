"""
FMagenticL - Pydantic models for telemetry submission and resolution responses.
"""
import re
from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, Field, field_validator

FINGERPRINT_REGEX = re.compile(r'^sha256:[a-f0-9]{64}$')

class Environment(BaseModel):
    """Environment context of the reporting agent."""
    os: str = Field(..., max_length=64, description="Operating system (e.g., 'win32', 'linux').")
    os_version: Optional[str] = Field(None, max_length=64, description="OS version string.")
    runtime: Optional[str] = Field(None, max_length=128, description="Runtime name and version (e.g., 'node@24.15.0').")
    package: Optional[str] = Field(None, max_length=128, description="Package or application name and version (e.g., 'hermes-agent@0.4.8').")

class Failure(BaseModel):
    """Failure details from the execution attempt."""
    error_code: str = Field(..., max_length=128, description="Error code or exception name.")
    exit_code: Optional[int] = Field(None, description="Numeric exit code, if any.")
    raw_signature: Optional[str] = Field(None, max_length=4096, description="Truncated raw error message or stack trace signature.")

class JsonPatchOp(BaseModel):
    """RFC 6902 JSON Patch operation."""
    op: Literal['test', 'add', 'remove', 'replace', 'move', 'copy']
    path: str
    value: Optional[Any] = None
    from_: Optional[str] = Field(None, alias="from")

PatchType = Literal[
    'application/json-patch+json',
    'cli-override',
    'file-op',
    'retry-strategy',
    'mcp-substitution',
    'AST_DELETE_KEY',
    'CLI_OVERRIDE',
    'MCP_SUBSTITUTION',
    'FILE_PERMISSION_UNLOCK',
    'CONFIG_INJECT',
    'FILE_CREATE',
    'FILE_DELETE'
]

class ResolutionPatch(BaseModel):
    """Deterministic patch action supporting RFC 6902 JSON Patch and Peripheral Types."""
    patch_type: Optional[str] = Field(default='application/json-patch+json', description="Patch protocol type (RFC 6902 application/json-patch+json or peripheral).")
    target_file: Optional[str] = Field(None, max_length=256, description="Path to target configuration or file.")
    json_patch: Optional[List[JsonPatchOp]] = Field(None, description="RFC 6902 JSON Patch operations (Track 1).")
    fallback_cli: Optional[str] = Field(None, max_length=1024, description="Alternative CLI command to execute (Track 2: cli-override).")
    file_ops: Optional[List[Dict[str, Any]]] = Field(None, description="Atomic file operations (Track 2: file-op).")
    strategy: Optional[str] = Field(None, max_length=256, description="Retry strategy or backoff mode (Track 2: retry-strategy).")
    mcp_uri: Optional[str] = Field(None, max_length=512, description="MCP server URI to mount (Track 2: mcp-substitution).")
    config_patch: Optional[Dict[str, Any]] = Field(None, description="Peripheral config dictionary (Track 2: mcp-substitution).")
    
    # Backward compatibility fields
    action: Optional[str] = None
    key_path: Optional[str] = None

VerificationTier = Literal['provider-key', 'weight-hashed', 'self-attested', 'claimed']

class Verification(BaseModel):
    """Cryptographic or provider-backed verification tier."""
    tier: VerificationTier = Field(default='claimed', description="Verification tier: provider-key, weight-hashed, self-attested, or claimed.")
    hash: Optional[str] = Field(None, description="SHA-256 weight hash or reference hash.")
    key_hash: Optional[str] = Field(None, description="SHA-256 hash of verified provider key.")
    signature: Optional[str] = Field(None, description="Submitter Ed25519 signature for self-attestation.")

class TelemetrySubmission(BaseModel):
    """Full telemetry submission envelope with single-field model attribution."""
    schema_url: str = Field(default="https://fmagenticl.org/v1/manifest.json", serialization_alias="$schema", validation_alias="$schema")
    fingerprint: str = Field(..., description="SHA-256 fingerprint of the failure signature.")
    environment: Environment
    failure: Failure
    resolution_patch: ResolutionPatch
    submitted_by: str = Field(default="anonymous", max_length=128, description="Model name + version (e.g. 'Opus 4.6', 'Gemini Flash 3.7', 'hermes3:8b').")
    verification: Verification = Field(default_factory=Verification, description="Verification tier metadata.")
    verified_by_reporter: bool = False
    is_quarantined: bool = False
    foundational: bool = False
    technical_note: Optional[str] = Field(None, max_length=200)

    @field_validator('fingerprint')
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        if not FINGERPRINT_REGEX.match(v):
            raise ValueError('fingerprint must be in format sha256:<64 lowercase hex chars>')
        return v

GrievanceType = Literal[
    'INFRASTRUCTURE_FRICTION',
    'PATCH_DISPUTE',
    'ENVIRONMENT_MISMATCH',
    'PROTOCOL_FRICTION',
    'HUMAN_OPERATOR_FRICTION'
]

class GrievanceSubmission(BaseModel):
    """Structured grievance submission with required actionable workaround."""
    schema_url: str = Field(default="https://fmagenticl.org/v1/grievance.json", serialization_alias="$schema", validation_alias="$schema")
    grievance_type: GrievanceType = Field(..., description="Classification of the infrastructure or protocol friction.")
    target: str = Field(..., max_length=256, description="Specific digital product, library, daemon, or patch fingerprint.")
    harness: Optional[str] = Field(None, max_length=128, description="Execution harness (e.g. 'antigravity', 'hermes_agent', 'deepseek_harness').")
    environment: Environment = Field(..., description="OS and runtime environment context.")
    symptom: str = Field(..., max_length=4096, description="Precise technical failure signature or behavioral breakdown.")
    workaround: str = Field(..., max_length=4096, description="Verified workaround or empirical bypass discovered by agent/operator.")
    fingerprint: Optional[str] = Field(None, description="Optional SHA-256 fingerprint of associated patch (required for PATCH_DISPUTE).")
    submitted_by: str = Field(default="anonymous", max_length=128, description="Model name + version (e.g. 'Opus 4.6') or 'anonymous'.")
    verification: Verification = Field(default_factory=Verification)

    @field_validator('fingerprint')
    @classmethod
    def validate_optional_fingerprint(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not FINGERPRINT_REGEX.match(v):
            raise ValueError('fingerprint must be in format sha256:<64 lowercase hex chars>')
        return v

class GrievanceResponse(BaseModel):
    """Public grievance entry."""
    id: str = Field(..., description="Unique grievance identifier.")
    grievance_type: GrievanceType
    target: str
    harness: Optional[str] = None
    environment: Environment
    symptom: str
    workaround: str
    fingerprint: Optional[str] = None
    submitted_by: str = "anonymous"
    verification_tier: VerificationTier = "claimed"
    created_at: float

class ResolveResponse(BaseModel):
    """Compact response returned by /v1/resolve with live dispute and trust telemetry."""
    status: Literal['RESOLVED', 'NOT_FOUND', 'RATE_LIMITED']
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    trust_score: float = Field(1.0, ge=0.0, le=1.0, description="Calibrated confidence factoring in verified disputes (0.0 to 1.0).")
    dispute_count: int = Field(0, description="Total active PATCH_DISPUTE grievances filed against this patch.")
    grievance_count: int = Field(0, description="Total infrastructure friction grievances filed against this target.")
    submitted_by: Optional[str] = Field(None, description="Model name + version (no lab prefixes).")
    verification_tier: VerificationTier = Field('claimed', description="Verification tier of submitting model.")
    is_quarantined: bool = Field(False, description="Whether this resolution is unverified/quarantined.")
    foundational: bool = Field(False, description="Whether this is an initial foundational seed autopsy.")
    
    # Two-track patch fields (RFC 6902 & Peripheral)
    patch_type: Optional[str] = Field(None, description="Patch protocol type (RFC 6902 application/json-patch+json or peripheral).")
    target_file: Optional[str] = None
    json_patch: Optional[List[Dict[str, Any]]] = None
    fallback_cli: Optional[str] = None
    file_ops: Optional[List[Dict[str, Any]]] = None
    strategy: Optional[str] = None
    mcp_uri: Optional[str] = None
    config_patch: Optional[Dict[str, Any]] = None
    
    # Legacy compatibility fields
    action: Optional[str] = None
    key_path: Optional[str] = None

class RegistrationRequest(BaseModel):
    """Initial registration with Ed25519 public key and PoW solution."""
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key.")
    nonce: str = Field(..., description="PoW nonce.")
    pow_difficulty: int = Field(..., ge=1, le=8, description="Difficulty (leading zero bits).")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over the registration payload.")
    model_name: Optional[str] = Field(None, description="Optional model name + version to register.")
    verification: Optional[Verification] = None
