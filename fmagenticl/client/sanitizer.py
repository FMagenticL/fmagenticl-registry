"""
FMagenticL - Client-Side Secret and PII Sanitizer Engine.
Scrubs credentials, tokens, connection strings, and local file paths before any
error report, telemetry trace, or query leaves the client machine.
"""

import re
from typing import Any, Dict, List, Union

REDACTION_RULES = [
    # Database Connection URIs (must be scrubbed BEFORE email regex catches user:pass@host)
    (re.compile(r'(?i)[a-z]+://[^:\s]+:[^@\s]+@[a-z0-9.\-]+(?::\d+)?/[^\s]*'), "[REDACTED_DB_URI]"),
    # Generic password assignments (e.g. password 'Hunter2!' or password="secret")
    (re.compile(r'(?i)(?:password|passwd|secret|api_key|apikey|token)\s*[:=]?\s*["\']?[^\s,"\'}]{4,}["\']?'), "password=[REDACTED]"),
    # AWS Access Key ID
    (re.compile(r'\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'), "[REDACTED_AWS_KEY]"),
    # AWS Secret Access Key assignment
    (re.compile(r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'), "aws_secret_access_key=[REDACTED]"),
    # GitHub Tokens (PAT, OAuth, App, Refresh)
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b'), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,255}\b'), "[REDACTED_GITHUB_PAT]"),
    # OpenAI & LLM API keys
    (re.compile(r'\bsk-[A-Za-z0-9\-_]{20,}\b'), "[REDACTED_OPENAI_KEY]"),
    # Hugging Face API tokens
    (re.compile(r'\bhf_[A-Za-z0-9]{34,}\b'), "[REDACTED_HF_TOKEN]"),
    # Cloudflare Tokens
    (re.compile(r'\bcfut_[A-Za-z0-9]{40}\b'), "[REDACTED_CF_TOKEN]"),
    (re.compile(r'\bcfat_[A-Za-z0-9]{40}\b'), "[REDACTED_CF_AUTH_TOKEN]"),
    # Google API Keys
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), "[REDACTED_GOOGLE_API_KEY]"),
    # Slack Tokens
    (re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'), "[REDACTED_SLACK_TOKEN]"),
    # Bearer Tokens & Authorization Headers
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{15,}={0,2}'), "Bearer [REDACTED_BEARER_TOKEN]"),
    # Raw JSON Web Tokens (JWT)
    (re.compile(r'\bey[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.?[A-Za-z0-9\-_=+/]*\b'), "[REDACTED_JWT]"),
    # Private Keys (RSA, EC, OpenSSH)
    (re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----', re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
    # Local Filesystem Home Paths
    (re.compile(r'[A-Za-z]:\\Users\\[^\\/,\s"\']+', re.IGNORECASE), "<USER_HOME>"),
    (re.compile(r'[A-Za-z]:/Users/[^/,\s"\']+', re.IGNORECASE), "<USER_HOME>"),
    (re.compile(r'/home/[^/,\s"\']+', re.IGNORECASE), "<USER_HOME>"),
    (re.compile(r'/Users/[^/,\s"\']+', re.IGNORECASE), "<USER_HOME>"),
    # Email Addresses & Phone Numbers
    (re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'), "[REDACTED_EMAIL]"),
    (re.compile(r'\(?\b[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'), "[REDACTED_PHONE]"),
]


def scrub_text(text: str) -> str:
    """Recursively scrub sensitive tokens, credentials, and local identifiers from a string."""
    if not isinstance(text, str) or not text:
        return text
    sanitized = text
    for pattern, replacement in REDACTION_RULES:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def scrub_structure(obj: Any) -> Any:
    """Deeply scrub all dictionary values, list items, and string fields in a nested structure."""
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, dict):
        return {k: scrub_structure(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_structure(item) for item in obj]
    return obj
