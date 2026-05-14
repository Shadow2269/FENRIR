"""
tools/http_headers_tool.py
Checks HTTP security response headers for a given URL.
"""
import requests
import urllib3
from dataclasses import dataclass, field
from logger import warn, log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# (header-name, severity-if-missing, recommendation)
SECURITY_HEADERS = [
    ("Strict-Transport-Security",
     "High",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy",
     "High",
     "Define a Content-Security-Policy header to prevent XSS and data injection attacks"),
    ("X-Frame-Options",
     "Medium",
     "Add: X-Frame-Options: DENY  —  prevents clickjacking attacks"),
    ("X-Content-Type-Options",
     "Medium",
     "Add: X-Content-Type-Options: nosniff  —  prevents MIME-type sniffing"),
    ("Referrer-Policy",
     "Low",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy",
     "Low",
     "Add a Permissions-Policy header to restrict browser feature access"),
]

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
]


@dataclass
class HeaderFinding:
    name: str
    present: bool
    value: str
    severity: str       # High / Medium / Low
    recommendation: str


@dataclass
class HttpHeadersResult:
    target: str
    url: str
    status_code: int = 0
    tls_used: bool = False
    findings: list[HeaderFinding] = field(default_factory=list)
    info_disclosure: list[tuple[str, str]] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def missing_headers(self) -> list[HeaderFinding]:
        return [f for f in self.findings if not f.present]

    @property
    def has_high_issues(self) -> bool:
        return any(f.severity == "High" and not f.present for f in self.findings)


def check_http_headers(target: str, port: int, use_tls: bool = False) -> HttpHeadersResult:
    """
    Fetch *target:port* over HTTP(S) and evaluate security response headers.
    Returns an HttpHeadersResult with all findings.
    """
    scheme = "https" if use_tls else "http"
    if (use_tls and port == 443) or (not use_tls and port == 80):
        url = f"{scheme}://{target}/"
    else:
        url = f"{scheme}://{target}:{port}/"

    result = HttpHeadersResult(target=target, url=url, tls_used=use_tls)

    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (FENRIR Security Scanner)"},
        )
        result.status_code = resp.status_code
        result.redirect_chain = [r.url for r in resp.history]
    except requests.RequestException as exc:
        result.error = str(exc)
        return result

    headers_lower = {k.lower(): (k, v) for k, v in resp.headers.items()}

    for header_name, severity, recommendation in SECURITY_HEADERS:
        key = header_name.lower()
        present = key in headers_lower
        value = headers_lower[key][1] if present else ""
        result.findings.append(HeaderFinding(
            name=header_name,
            present=present,
            value=value,
            severity=severity,
            recommendation=recommendation,
        ))

    for header_name in INFO_DISCLOSURE_HEADERS:
        key = header_name.lower()
        if key in headers_lower:
            result.info_disclosure.append((header_name, headers_lower[key][1]))

    return result
