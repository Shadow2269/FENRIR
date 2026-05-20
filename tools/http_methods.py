"""
tools/http_methods.py
Tests which HTTP methods are enabled on a web endpoint.
Dangerous methods like PUT, DELETE, TRACE, and CONNECT can indicate
misconfigurations that allow data modification or info disclosure.
"""
import requests
import urllib3
from dataclasses import dataclass, field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10

# (method, dangerous, detail)
_METHODS_TO_TEST: list[tuple[str, bool, str]] = [
    ("OPTIONS",  False, "Lists allowed methods — information disclosure"),
    ("GET",      False, "Standard read method"),
    ("HEAD",     False, "Standard header-only request"),
    ("POST",     False, "Standard write method"),
    ("PUT",      True,  "May allow arbitrary file upload or resource creation"),
    ("DELETE",   True,  "May allow deletion of server resources"),
    ("PATCH",    False, "Partial resource modification"),
    ("TRACE",    True,  "Echoes request back — enables Cross-Site Tracing (XST)"),
    ("CONNECT",  True,  "Tunnel support — proxy abuse risk"),
    ("PROPFIND", True,  "WebDAV — exposes directory listings"),
    ("MKCOL",    True,  "WebDAV — allows directory creation"),
    ("MOVE",     True,  "WebDAV — allows resource relocation"),
    ("COPY",     True,  "WebDAV — allows resource duplication"),
]


@dataclass
class MethodFinding:
    method:      str
    status_code: int
    dangerous:   bool
    allowed:     bool   # True if server responded with 2xx or method-specific code
    detail:      str


@dataclass
class HTTPMethodsResult:
    success:  bool
    target:   str
    findings: list[MethodFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def dangerous_allowed(self) -> list[MethodFinding]:
        return [f for f in self.findings if f.dangerous and f.allowed]

    @property
    def has_findings(self) -> bool:
        return bool(self.dangerous_allowed)


def test_http_methods(url: str) -> HTTPMethodsResult:
    """
    Send each method in _METHODS_TO_TEST to *url* and record the response.
    Methods returning 2xx, 301, 302, or 405 are considered "reachable" (server
    processed them); anything else is treated as blocked/unsupported.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    # First try OPTIONS to get the Allow header quickly
    allowed_from_header: set[str] = set()
    try:
        opt = session.options(url, timeout=_TIMEOUT, allow_redirects=False)
        allow_hdr = opt.headers.get("Allow", "") or opt.headers.get("Public", "")
        allowed_from_header = {m.strip().upper() for m in allow_hdr.split(",")} if allow_hdr else set()
    except Exception:
        pass

    findings: list[MethodFinding] = []
    for method, dangerous, detail in _METHODS_TO_TEST:
        try:
            r = session.request(
                method, url, timeout=_TIMEOUT,
                allow_redirects=False,
                data=b"FENRIR-test" if method in ("PUT", "PATCH", "POST") else None,
            )
            status = r.status_code
            # 405 = Method Not Allowed (server knows the method but rejects it)
            # 501 = Not Implemented
            # 200-399 = definitely accepted
            allowed = status not in (405, 501, 403, 404) and status < 500
            findings.append(MethodFinding(
                method=method,
                status_code=status,
                dangerous=dangerous,
                allowed=allowed,
                detail=detail,
            ))
        except requests.RequestException:
            findings.append(MethodFinding(
                method=method, status_code=0,
                dangerous=dangerous, allowed=False,
                detail=detail,
            ))

    return HTTPMethodsResult(success=True, target=url, findings=findings)
