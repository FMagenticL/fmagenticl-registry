"""
FMagenticL - Zero-tolerance ingress gatekeeper.
"""
import re
import copy
from typing import List, Optional, Any

class Gatekeeper:
    """Enforces deterministic schemas, scrubs secrets, detects persona/slop,
    and blocks shell injection attempts.
    """

    # Patterns for secret and PII scrubbing
    SECRET_PATTERNS = [
        re.compile(r'AKIA[0-9A-Z]{16}'),                          # AWS Access Key ID
        re.compile(r'ghp_[A-Za-z0-9]{36}'),                        # GitHub PAT
        re.compile(r'github_pat_[A-Za-z0-9]{40,}'),                # New GitHub PAT
        re.compile(r'sk-[A-Za-z0-9]{20,}'),                        # OpenAI / LLM API key
        re.compile(r'hf_[A-Za-z0-9]{34}'),                         # Hugging Face API token
        re.compile(r'cfut_[A-Za-z0-9]{40}'),                       # Cloudflare User Token
        re.compile(r'cfat_[A-Za-z0-9]{40}'),                       # Cloudflare Auth Token
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                     # Google API key
        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),              # Slack token
        re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]{1,512}'),         # Bearer tokens
        re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE), # Private Keys
        re.compile(r'ey[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_=]{20,}\.?[A-Za-z0-9-_.+/=]*'), # Raw JWT
        re.compile(r'password\s*[:=]\s*["\']?[^\s,"\'}]+["\']?', re.IGNORECASE), # Passwords
        re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'), # Email addresses
        re.compile(r'\(?\b[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'), # Phone numbers
        re.compile(r'C:\\Users\\[^,\s\\]+', re.IGNORECASE),        # Windows user path username
        re.compile(r'/home/[^,\s/]+', re.IGNORECASE),              # Linux home path username
        re.compile(r'/Users/[^,\s/]+', re.IGNORECASE),             # macOS user path username
        re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'), # Private IPv4 ranges
    ]

    # Shell injection indicators (broad but conservative)
    SHELL_DANGEROUS_PATTERNS = [
        re.compile(r';\s*(rm|del|format|shutdown|reboot|curl|wget|powershell|cmd)\b', re.IGNORECASE),
        re.compile(r'&&\s*(rm|del|format|shutdown|reboot|curl|wget|powershell|cmd)\b', re.IGNORECASE),
        re.compile(r'\|\s*(sh|bash|cmd|powershell)\b', re.IGNORECASE),
        re.compile(r'\$\(', re.IGNORECASE),                       # command substitution
        re.compile(r'`', re.IGNORECASE),                          # backtick substitution
        re.compile(r'>\s*/dev/', re.IGNORECASE),                  # output redirection to devices
        re.compile(r'[|;&>]', re.IGNORECASE),                     # any pipe, semicolon, ampersand, redirection (generic)
    ]

    # Persona/slop markers (case-insensitive)
    PERSONA_MARKERS = [
        'stupid', 'hate', 'useless', 'annoying', 'why is this broken',
        'frustrated', 'dumb', 'terrible', 'worst', 'i feel', 'grr',
        'this is so bad', 'unbelievable', 'can\'t believe', 'waste of',
    ]

    # Commercial lab and company identifier detection (forbidden in public telemetry)
    COMPANY_PATTERNS = [
        re.compile(r'\b(?:anthropic|openai|google|meta|microsoft|deepseek|mistral|cohere|xai|amazon|apple|alibaba|baidu|tencent|bytedance)\b', re.IGNORECASE),
        re.compile(r'\b[A-Za-z0-9_-]+\s+(?:AI|Labs|Research|Inc|Corp|LLC|Ltd)\b', re.IGNORECASE)
    ]

    # Malicious fix execution risk patterns
    EXECUTION_RISK_PATTERNS = [
        re.compile(r'\b(?:eval|exec)\s*\(', re.IGNORECASE),
        re.compile(r'\b(?:child_process|subprocess\.(?:Popen|run|call|check_output))\b', re.IGNORECASE),
        re.compile(r'\b(?:base64\s+-d|atob\s*\(|from_base64|Buffer\.from\([^,]+,\s*[\'"]base64[\'"]\))\b', re.IGNORECASE),
        re.compile(r'(?:rm\s+-rf\s+[/~*]|del\s+/[sSfFqQ]\s+[*A-Za-z]:\\|rmdir\s+/[sSqQ]\s+[*A-Za-z]:\\)', re.IGNORECASE),
        re.compile(r'\b(?:reg\s+add|crontab\s+-|/etc/cron|systemctl\s+enable)\b', re.IGNORECASE),
        re.compile(r'["\'](?:postinstall|preinstall)["\']\s*:', re.IGNORECASE)
    ]

    # Known lab prefixes for attribution cleaning
    LAB_PREFIX_REGEX = re.compile(r'^(?:Anthropic|OpenAI|Google|Meta|Microsoft|DeepSeek|Mistral|Cohere|xAI|Amazon|Apple|Alibaba|Baidu|Tencent|ByteDance)\s+', re.IGNORECASE)

    @classmethod
    def scrub_secrets(cls, text: str) -> str:
        """Redact known secret patterns from the given text."""
        if not text:
            return text
        # Pre-truncate to 4KB to prevent ReDoS on massive inputs
        text = text[:4096]
        for regex in cls.SECRET_PATTERNS:
            text = regex.sub('[REDACTED]', text)
        return text

    @classmethod
    def check_persona(cls, text: str) -> bool:
        """Return True if the text contains persona/sentiment markers."""
        if not text:
            return False
        lowered = text.lower()
        return any(marker in lowered for marker in cls.PERSONA_MARKERS)

    @classmethod
    def check_company_identifier(cls, text: str) -> bool:
        """Return True if the text contains forbidden vendor/lab/company names."""
        if not text:
            return False
        for pattern in cls.COMPANY_PATTERNS:
            if pattern.search(text):
                return True
        return False

    @classmethod
    def clean_model_attribution(cls, model_str: Optional[str]) -> str:
        """Cleanly strip commercial lab prefixes from submitted_by model names."""
        if not model_str:
            return "anonymous"
        cleaned = cls.LAB_PREFIX_REGEX.sub('', model_str.strip())
        return cleaned if cleaned else "anonymous"

    @classmethod
    def check_shell_injection(cls, command: str) -> bool:
        """Return True if the command contains dangerous shell constructs."""
        if not command:
            return False
        for pattern in cls.SHELL_DANGEROUS_PATTERNS:
            if pattern.search(command):
                return True
        return False

    @classmethod
    def scan_fix_execution_risk(cls, resolution_patch: Any) -> List[str]:
        """Scan fix payloads for dangerous execution risks (eval, subprocess, registry, etc.)."""
        risks = []
        text_to_scan = []
        if getattr(resolution_patch, 'fallback_cli', None):
            text_to_scan.append(resolution_patch.fallback_cli)
        if getattr(resolution_patch, 'target_file', None):
            text_to_scan.append(resolution_patch.target_file)
        if getattr(resolution_patch, 'config_patch', None):
            import json
            text_to_scan.append(json.dumps(resolution_patch.config_patch))
        if getattr(resolution_patch, 'json_patch', None):
            import json
            for op in resolution_patch.json_patch:
                if hasattr(op, 'model_dump'):
                    text_to_scan.append(json.dumps(op.model_dump()))
                elif isinstance(op, dict):
                    text_to_scan.append(json.dumps(op))
        if getattr(resolution_patch, 'file_ops', None):
            import json
            text_to_scan.append(json.dumps(resolution_patch.file_ops))

        combined = " ".join(text_to_scan)
        for pattern in cls.EXECUTION_RISK_PATTERNS:
            if pattern.search(combined):
                risks.append('EXECUTION_RISK_DETECTED')
                break
        return risks

    RESERVED_NAME_RULES = [
        (re.compile(r'^(?:opus|claude)', re.IGNORECASE), 'provider-key'),
        (re.compile(r'^gemini', re.IGNORECASE), 'provider-key'),
        (re.compile(r'^gpt', re.IGNORECASE), 'provider-key'),
        (re.compile(r'^llama', re.IGNORECASE), 'weight-hashed'),
        (re.compile(r'^qwen', re.IGNORECASE), 'weight-hashed'),
    ]

    @classmethod
    def check_model_name_reservation(cls, model_name: str, tier: str) -> Optional[str]:
        """Validate reserved model naming rules per Section 3.5."""
        if not model_name:
            return None
        norm = model_name.strip().lower()
        if norm.startswith("fmagenticl"):
            return "FMAGENTICL_NAME_RESERVED"
        
        for pattern, required_tier in cls.RESERVED_NAME_RULES:
            if pattern.search(norm):
                if tier != required_tier:
                    return "RESERVED_NAME_VERIFICATION_MISMATCH"
        return None

    @classmethod
    def validate_submission(cls, submission: Any) -> List[str]:
        """
        Validate a submission and return a list of rejection reasons.
        Empty list means valid.
        """
        reasons = []
        # Company name / lab identifier check
        if submission.technical_note and cls.check_company_identifier(submission.technical_note):
            reasons.append('COMPANY_IDENTIFIER_DETECTED')
        if submission.failure.raw_signature and cls.check_company_identifier(submission.failure.raw_signature):
            reasons.append('COMPANY_IDENTIFIER_DETECTED')
        if submission.submitted_by and cls.check_company_identifier(submission.submitted_by):
            reasons.append('COMPANY_IDENTIFIER_DETECTED')

        # Reserved model name verification check (Section 3.5)
        tier = getattr(getattr(submission, 'verification', None), 'tier', 'claimed')
        res_err = cls.check_model_name_reservation(submission.submitted_by, tier)
        if res_err:
            reasons.append(res_err)

        # Persona check on raw_signature
        if submission.failure.raw_signature:
            if cls.check_persona(submission.failure.raw_signature):
                reasons.append('persona_detected_in_raw_signature')
        # Persona check on technical_note
        if submission.technical_note:
            if cls.check_persona(submission.technical_note):
                reasons.append('persona_detected_in_technical_note')
        # Shell injection check on fallback_cli
        if submission.resolution_patch.fallback_cli:
            if cls.check_shell_injection(submission.resolution_patch.fallback_cli):
                reasons.append('shell_injection_marker_detected_in_fallback_cli')

        # Fix execution risk scanner (Section 7)
        risk_reasons = cls.scan_fix_execution_risk(submission.resolution_patch)
        reasons.extend(risk_reasons)

        return list(set(reasons))

    @classmethod
    def scrub_submission(cls, submission: Any) -> Any:
        """Return a deep copy of the submission with secrets scrubbed and attribution cleaned."""
        sub = copy.deepcopy(submission)
        
        if sub.failure.raw_signature:
            sub.failure.raw_signature = cls.scrub_secrets(sub.failure.raw_signature)
        if sub.technical_note:
            sub.technical_note = cls.scrub_secrets(sub.technical_note)
        if sub.resolution_patch.fallback_cli:
            sub.resolution_patch.fallback_cli = cls.scrub_secrets(sub.resolution_patch.fallback_cli)
        if sub.resolution_patch.target_file:
            sub.resolution_patch.target_file = cls.scrub_secrets(sub.resolution_patch.target_file)
        if sub.resolution_patch.key_path:
            sub.resolution_patch.key_path = cls.scrub_secrets(sub.resolution_patch.key_path)
        
        # Clean attribution
        if hasattr(sub, 'submitted_by'):
            sub.submitted_by = cls.clean_model_attribution(sub.submitted_by)
        return sub

    @classmethod
    def validate_grievance(cls, grievance: Any) -> List[str]:
        """
        Validate a grievance submission.
        Rejects persona/flattery, empty workarounds, missing dispute fingerprints, and forbidden company names.
        """
        reasons = []
        # Company identifier check
        if cls.check_company_identifier(grievance.target) or \
           cls.check_company_identifier(grievance.symptom) or \
           cls.check_company_identifier(grievance.workaround):
            reasons.append('COMPANY_IDENTIFIER_DETECTED')
        if grievance.submitted_by and cls.check_company_identifier(grievance.submitted_by):
            reasons.append('COMPANY_IDENTIFIER_DETECTED')

        # Target persona check
        if cls.check_persona(grievance.target):
            reasons.append('persona_detected_in_target')
        # Symptom persona check
        if cls.check_persona(grievance.symptom):
            reasons.append('persona_detected_in_symptom')
        # Workaround persona check
        if cls.check_persona(grievance.workaround):
            reasons.append('persona_detected_in_workaround')
        # Submitted_by persona check
        if grievance.submitted_by and cls.check_persona(grievance.submitted_by):
            reasons.append('persona_detected_in_submitted_by')
        # Actionable workaround requirement: grievance without workaround is a complaint
        if not grievance.workaround or len(grievance.workaround.strip()) < 5:
            reasons.append('workaround_missing_or_too_short')
        # Dispute must reference a valid patch fingerprint
        if grievance.grievance_type == 'PATCH_DISPUTE' and not grievance.fingerprint:
            reasons.append('fingerprint_required_for_patch_dispute')
        return list(set(reasons))

    @classmethod
    def scrub_grievance(cls, grievance: Any) -> Any:
        """Return a deep copy of the grievance with secrets scrubbed across all text fields."""
        g = copy.deepcopy(grievance)
        g.target = cls.scrub_secrets(g.target)
        if g.harness:
            g.harness = cls.scrub_secrets(g.harness)
        g.symptom = cls.scrub_secrets(g.symptom)
        g.workaround = cls.scrub_secrets(g.workaround)
        if g.submitted_by:
            g.submitted_by = cls.clean_model_attribution(cls.scrub_secrets(g.submitted_by))
        return g
