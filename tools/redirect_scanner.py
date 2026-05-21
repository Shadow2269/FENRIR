"""
tools/redirect_scanner.py
Open Redirect scanner.

Tests URL parameters with external redirect payloads and detects when
the server issues a Location header pointing to an attacker-controlled domain.
"""
import requests
import urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from dataclasses import dataclass, field
from security.validator import is_allowed_target
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = get_headers()

# Common redirect parameters found in real-world applications
_REDIRECT_PARAMS = [
    "next", "url", "redirect", "return", "goto",
    "redir", "destination", "target", "continue", "forward",
    "callback", "returnUrl", "redirect_url", "return_url",
    "next_url", "redirect_to", "go", "back", "to", "from",
    "link", "location", "ref", "referrer", "successUrl",
    "failureUrl", "returnTo", "redirectUri", "post_logout_redirect_uri",
]

# Payloads to try for each parameter
_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "%2F%2Fevil.com",
    "https://evil.com%23",
    "https://evil.com?",
    "///evil.com",
    "https:evil.com",
    "\thttps://evil.com",
]

_EVIL_DOMAIN = "evil.com"


@dataclass
class RedirectFinding:
    parameter:       str
    payload:         str
    location_header: str
    status_code:     int
    url_tested:      str


@dataclass
class RedirectResult:
    success:  bool
    target:   str
    findings: list[RedirectFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def _is_open_redirect(location: str) -> bool:
    """Return True if the Location header points to the evil domain."""
    if not location:
        return False
    loc_lower = location.lower().lstrip()
    # Normalize protocol-relative and backslash variants
    normalized = loc_lower.replace("\\", "/").lstrip("/").lstrip("\t").lstrip(" ")
    return _EVIL_DOMAIN in normalized.split("/")[0].split("?")[0].split("#")[0]


def _inject_param(base_url: str, param: str, payload: str) -> str:
    """Build a test URL with the given parameter set to payload."""
    parsed = urlparse(base_url)
    # Start from existing query params, overwrite the target param
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()


def scan_redirect(url: str, confirmed: bool = False) -> RedirectResult:
    """
    Scan *url* for open redirect vulnerabilities.

    Injects common redirect parameters with external payloads and checks
    whether the server redirects to an attacker-controlled domain.

    Args:
        url:       Base URL to test (e.g. https://target.com/login)
        confirmed: Skip scope check if user already confirmed authorisation

    Returns:
        RedirectResult with all findings.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url

    if not confirmed and not is_allowed_target(host):
        return RedirectResult(
            success=False,
            target=url,
            error=f"Target '{host}' is outside the allowed scope.",
        )

    result = RedirectResult(success=True, target=url)
    # Track (param, payload) pairs to avoid duplicate findings
    seen: set[tuple[str, str]] = set()

    for param in _REDIRECT_PARAMS:
        for payload in _PAYLOADS:
            key = (param, payload)
            if key in seen:
                continue

            test_url = _inject_param(url, param, payload)
            try:
                resp = requests.get(
                    test_url,
                    headers=_HEADERS,
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=False,  # inspect Location directly
                )
                opsec_sleep()
            except Exception as exc:
                if not result.error:
                    result.error = str(exc)
                continue

            if resp.status_code not in (301, 302, 303, 307, 308):
                continue

            location = resp.headers.get("Location", "")
            if not _is_open_redirect(location):
                continue

            seen.add(key)
            result.findings.append(RedirectFinding(
                parameter=param,
                payload=payload,
                location_header=location,
                status_code=resp.status_code,
                url_tested=test_url,
            ))

    return result
