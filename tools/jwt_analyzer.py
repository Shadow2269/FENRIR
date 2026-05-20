"""
tools/jwt_analyzer.py
Analyses a JWT token for known security weaknesses:
  - Algorithm: none (unsigned token accepted?)
  - Weak HMAC secret (wordlist bruteforce via hmac)
  - RS256 → HS256 algorithm confusion
  - Expired token (exp claim)
  - Sensitive data in payload (PII, admin flags, internal roles)

No external dependencies — uses only Python stdlib (base64, hmac, hashlib, json).
"""
import base64
import hmac
import hashlib
import json
import time
from dataclasses import dataclass, field


@dataclass
class JWTFinding:
    check_name: str
    severity:   str   # "Critical" | "High" | "Medium" | "Low" | "Info"
    detail:     str


@dataclass
class JWTResult:
    success:       bool
    token_preview: str   # first 20 + "..." + last 10 chars
    header:        dict  = field(default_factory=dict)
    payload:       dict  = field(default_factory=dict)
    findings:      list[JWTFinding] = field(default_factory=list)
    error:         str   = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def critical_findings(self) -> list[JWTFinding]:
        return [f for f in self.findings if f.severity == "Critical"]


# ── Top-1000 weak secrets (condensed list — extend as needed) ─────────────────

_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "abc123", "pass", "test", "jwt", "token",
    "key", "private", "supersecret", "changeme", "default", "root",
    "topsecret", "auth", "access", "refresh", "signature", "hmac",
    "1234567890", "0987654321", "HS256", "RS256", "your-256-bit-secret",
    "your-secret-key", "mysecret", "mypassword", "secretkey", "jwtkey",
    "jwt_secret", "app_secret", "SESSION_SECRET", "FLASK_SECRET",
    "django-insecure", "laravel", "symfony", "rails", "express",
    "node_secret", "api_key", "apikey", "API_KEY", "APP_KEY",
]

# Payload keys that may expose sensitive information
_SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "credit_card", "ssn", "social_security", "dob", "date_of_birth",
    "admin", "is_admin", "role", "roles", "permissions", "scope",
    "internal", "debug", "env", "environment",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _parse_parts(token: str) -> tuple[dict, dict, str] | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


# ── Main analyser ─────────────────────────────────────────────────────────────

def analyze_jwt(token: str) -> JWTResult:
    token = token.strip()
    preview = (token[:20] + "..." + token[-10:]) if len(token) > 33 else token

    parsed = _parse_parts(token)
    if not parsed:
        return JWTResult(
            success=False, token_preview=preview,
            error="Invalid JWT format — expected three base64url-encoded segments separated by '.'",
        )

    header, payload, signature = parsed
    findings: list[JWTFinding] = []
    parts = token.split(".")

    # ── Check 1: alg:none ────────────────────────────────────────────────────
    alg = header.get("alg", "").lower()
    if alg in ("none", "null", ""):
        findings.append(JWTFinding(
            check_name="Algorithm: none",
            severity="Critical",
            detail="Token uses alg:none — no signature verification. Any modified token will be accepted.",
        ))

    # ── Check 2: Weak HMAC secret ────────────────────────────────────────────
    if alg.startswith("hs"):
        bits = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
        hash_fn = bits.get(alg, hashlib.sha256)
        for secret in _WEAK_SECRETS:
            msg = f"{parts[0]}.{parts[1]}".encode()
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), msg, hash_fn).digest()
            ).rstrip(b"=").decode()
            if expected == signature:
                findings.append(JWTFinding(
                    check_name="Weak HMAC secret",
                    severity="Critical",
                    detail=f"Secret cracked: '{secret}' — attacker can forge arbitrary tokens.",
                ))
                break

    # ── Check 3: RS256 → HS256 algorithm confusion ───────────────────────────
    if alg == "rs256":
        findings.append(JWTFinding(
            check_name="RS256 → HS256 confusion risk",
            severity="High",
            detail="Token uses RS256. If the server accepts HS256 tokens signed with the public key, "
                   "an algorithm confusion attack is possible. Verify the server rejects HS256 tokens.",
        ))

    # ── Check 4: Expired token ───────────────────────────────────────────────
    exp = payload.get("exp")
    if exp is not None:
        if isinstance(exp, (int, float)) and exp < time.time():
            findings.append(JWTFinding(
                check_name="Token expired",
                severity="Info",
                detail=f"exp claim {exp} is in the past. Token should be rejected by the server.",
            ))
    else:
        findings.append(JWTFinding(
            check_name="No expiry claim",
            severity="Medium",
            detail="Token has no 'exp' claim — it never expires and can be replayed indefinitely.",
        ))

    # ── Check 5: Sensitive data in payload ───────────────────────────────────
    for key, value in payload.items():
        if key.lower() in _SENSITIVE_KEYS:
            str_val = str(value)
            masked = str_val[:4] + "***" if len(str_val) > 4 else "***"
            findings.append(JWTFinding(
                check_name=f"Sensitive claim: '{key}'",
                severity="Medium" if key.lower() in ("admin", "is_admin", "role", "roles") else "Low",
                detail=f"Payload contains '{key}': {masked} — JWTs are base64-encoded, not encrypted. "
                       "Anyone who intercepts the token can read this value.",
            ))

    # ── Check 6: Admin/elevated role ─────────────────────────────────────────
    for key in ("admin", "is_admin", "is_superuser"):
        if payload.get(key) in (True, "true", "1", 1):
            findings.append(JWTFinding(
                check_name=f"Admin flag: '{key}'",
                severity="High",
                detail=f"Token grants admin/elevated privileges via '{key}': {payload[key]}. "
                       "If the secret is weak or alg:none is accepted, privilege escalation is trivial.",
            ))

    return JWTResult(
        success=True,
        token_preview=preview,
        header=header,
        payload=payload,
        findings=findings,
    )
