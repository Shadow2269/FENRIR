"""
tools/cors_scanner.py
CORS misconfiguration scanner.

Tests a URL with crafted Origin headers and classifies the response:
  Critical — origin reflected 1:1 + Access-Control-Allow-Credentials: true
  High     — null origin accepted + credentials, or wildcard + credentials
  Medium   — origin reflected without credentials / wildcard without credentials
  Low      — non-standard but non-exploitable behaviour
"""
import requests
import urllib3
from urllib.parse import urlparse
from dataclasses import dataclass, field
from security.validator import is_allowed_target
from logger import warn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = {"User-Agent": "Mozilla/5.0 (FENRIR security scanner)"}


@dataclass
class CORSFinding:
    origin_sent:  str
    acao_header:  str    # Access-Control-Allow-Origin value
    acac_header:  str    # Access-Control-Allow-Credentials value
    severity:     str    # Critical | High | Medium | Low
    detail:       str


@dataclass
class CORSResult:
    success: bool
    target:  str
    findings: list[CORSFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "Critical" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == "High" for f in self.findings)

    @property
    def worst_severity(self) -> str:
        for sev in ("Critical", "High", "Medium", "Low"):
            if any(f.severity == sev for f in self.findings):
                return sev
        return "None"


def _build_test_origins(url: str) -> list[str]:
    """Generate crafted origins to test against the target URL."""
    parsed  = urlparse(url)
    host    = parsed.hostname or ""
    scheme  = parsed.scheme or "https"

    return [
        # Simple external origin — baseline
        "https://evil.com",
        # Null origin — exploitable via sandboxed iframes
        "null",
        # Suffix bypass: attacker registers target.com.evil.com
        f"https://{host}.evil.com",
        # Prefix bypass: attacker registers evil-target.com
        f"https://evil-{host}",
        # Subdomain confusion: evil.target.com (may not be registered)
        f"https://evil.{host}",
        # Protocol downgrade: HTTP instead of HTTPS
        f"http://{host}",
        # Backtick injection (rare server-side parsing bug)
        f"https://{host}`.evil.com",
    ]


def _classify(origin_sent: str, acao: str, acac: str) -> tuple[str, str] | None:
    """
    Return (severity, detail) if the combination is a finding, else None.
    acac is 'true' or '' (empty = not present / not true).
    """
    has_creds = acac.lower() == "true"
    acao_l    = acao.lower().strip()

    # Wildcard with credentials — spec disallows it but some servers send it
    if acao_l == "*" and has_creds:
        return (
            "High",
            "Access-Control-Allow-Origin: * combined with Allow-Credentials: true. "
            "Browsers block this per spec but the server is misconfigured and may "
            "behave unexpectedly with non-standard clients.",
        )

    # Wildcard without credentials — data exposure, no session hijack
    if acao_l == "*":
        return (
            "Medium",
            "Access-Control-Allow-Origin: * allows any website to read the response. "
            "No credential theft possible, but API data / tokens in the body may leak.",
        )

    # null origin + credentials → High (sandboxed iframe attack)
    if origin_sent == "null" and acao_l == "null" and has_creds:
        return (
            "High",
            "Server accepts 'null' origin and reflects it with Allow-Credentials: true. "
            "An attacker can exploit this via a sandboxed iframe to perform "
            "authenticated cross-origin requests.",
        )

    # null origin reflected without credentials → Medium
    if origin_sent == "null" and acao_l == "null":
        return (
            "Medium",
            "Server accepts and reflects the 'null' origin. "
            "Without credentials this limits the impact, but may still expose "
            "unauthenticated API responses.",
        )

    # Exact reflection of a hostile origin + credentials → Critical
    if acao == origin_sent and has_creds and origin_sent not in ("", "*"):
        return (
            "Critical",
            f"Origin '{origin_sent}' is reflected 1:1 in Access-Control-Allow-Origin "
            f"with Allow-Credentials: true. An attacker who controls '{origin_sent}' "
            "can make fully authenticated cross-origin requests on behalf of any logged-in user "
            "(session hijack, data exfiltration, CSRF bypass).",
        )

    # Reflection without credentials → Medium
    if acao == origin_sent and origin_sent not in ("", "*"):
        return (
            "Medium",
            f"Origin '{origin_sent}' is reflected in Access-Control-Allow-Origin. "
            "Without Allow-Credentials this cannot be used for session hijacking, "
            "but unauthenticated API responses are readable cross-origin.",
        )

    return None


def scan_cors(url: str, confirmed: bool = False) -> CORSResult:
    """
    Scan *url* for CORS misconfigurations.

    Args:
        url:       Full URL to test, e.g. https://api.example.com/v1/user
        confirmed: Skip scope check (user already confirmed authorisation)

    Returns:
        CORSResult with all findings.
    """
    parsed = urlparse(url)
    host   = parsed.hostname or url

    if not confirmed and not is_allowed_target(host):
        return CORSResult(
            success=False,
            target=url,
            error=f"Target '{host}' is outside the allowed scope.",
        )

    result  = CORSResult(success=True, target=url)
    origins = _build_test_origins(url)
    seen_severities: set[str] = set()

    for origin in origins:
        try:
            resp = requests.get(
                url,
                headers={**_HEADERS, "Origin": origin},
                timeout=_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:
            if not result.error:
                result.error = str(exc)
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        classified = _classify(origin, acao, acac)
        if classified is None:
            continue

        severity, detail = classified

        # Avoid duplicate severity entries for the same root cause
        dedup_key = f"{severity}:{acao}"
        if dedup_key in seen_severities:
            continue
        seen_severities.add(dedup_key)

        result.findings.append(CORSFinding(
            origin_sent=origin,
            acao_header=acao,
            acac_header=acac or "not set",
            severity=severity,
            detail=detail,
        ))

    return result
