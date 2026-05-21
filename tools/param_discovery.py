"""
tools/param_discovery.py
Hidden parameter discovery via GET and POST probing.

Loads a wordlist from wordlists/params.txt, injects each name into the
target URL, and compares the response length / status code to a baseline
to identify parameters the server reacts to.
"""
import os
import requests
import urllib3
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from security.validator import is_allowed_target
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT        = 8
_HEADERS        = get_headers()
_WORDLIST_PATH  = os.path.join(os.path.dirname(__file__), "..", "wordlists", "params.txt")
_PROBE_VALUE    = "FENRIR1337"
_LENGTH_DELTA   = 0.10      # 10 % length change → interesting
_MIN_BODY_LEN   = 10


@dataclass
class ParamFinding:
    name:             str
    method:           str    # GET | POST
    evidence:         str    # length_change | status_change | error_in_body
    baseline_length:  int
    found_length:     int
    status_code:      int


@dataclass
class ParamResult:
    success:  bool
    target:   str
    findings: list[ParamFinding] = field(default_factory=list)
    tested:   int                = 0
    error:    str                = ""

    @property
    def get_findings(self) -> list[ParamFinding]:
        return [f for f in self.findings if f.method == "GET"]

    @property
    def post_findings(self) -> list[ParamFinding]:
        return [f for f in self.findings if f.method == "POST"]


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_wordlist() -> list[str]:
    try:
        with open(_WORDLIST_PATH, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []


def _relative_diff(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 0.0
    return abs(a - b) / max(a, b)


def _get_baseline(url: str) -> tuple[int, int]:
    """Return (status_code, content_length) for the bare URL."""
    try:
        r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT,
                         verify=False, allow_redirects=True)
        opsec_sleep()
        return r.status_code, len(r.content)
    except Exception:
        return -1, 0


def _probe_get(url: str, param: str,
               base_status: int, base_len: int) -> ParamFinding | None:
    parsed = urlparse(url)
    qs     = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [_PROBE_VALUE]
    probed = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    try:
        r = requests.get(probed, headers=_HEADERS, timeout=_TIMEOUT,
                         verify=False, allow_redirects=True)
    except Exception:
        return None

    length = len(r.content)
    diff   = _relative_diff(base_len, length)

    if r.status_code != base_status and r.status_code not in (400, 404, 429):
        return ParamFinding(param, "GET", "status_change",
                            base_len, length, r.status_code)
    if base_len >= _MIN_BODY_LEN and length >= _MIN_BODY_LEN and diff >= _LENGTH_DELTA:
        return ParamFinding(param, "GET", "length_change",
                            base_len, length, r.status_code)
    body_lower = r.text.lower()
    if any(kw in body_lower for kw in ("sql", "error", "exception", "warning", "fatal")):
        return ParamFinding(param, "GET", "error_in_body",
                            base_len, length, r.status_code)
    return None


def _probe_post(url: str, param: str,
                base_status: int, base_len: int) -> ParamFinding | None:
    try:
        r = requests.post(url, data={param: _PROBE_VALUE},
                          headers=_HEADERS, timeout=_TIMEOUT,
                          verify=False, allow_redirects=True)
    except Exception:
        return None

    length = len(r.content)
    diff   = _relative_diff(base_len, length)

    if r.status_code != base_status and r.status_code not in (400, 404, 405, 429):
        return ParamFinding(param, "POST", "status_change",
                            base_len, length, r.status_code)
    if base_len >= _MIN_BODY_LEN and length >= _MIN_BODY_LEN and diff >= _LENGTH_DELTA:
        return ParamFinding(param, "POST", "length_change",
                            base_len, length, r.status_code)
    return None


# ── public API ────────────────────────────────────────────────────────────────

def discover_params(url: str, methods: list[str] | None = None,
                    confirmed: bool = False) -> ParamResult:
    """
    Probe *url* with every name from the params wordlist.

    methods — list of HTTP methods to test, default ["GET", "POST"].
    """
    if methods is None:
        methods = ["GET", "POST"]

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    hostname = urlparse(url).hostname or url

    if not is_allowed_target(hostname) and not confirmed:
        return ParamResult(success=False, target=hostname,
                           error=f"Target not in allowlist: {hostname}")

    wordlist = _load_wordlist()
    if not wordlist:
        return ParamResult(success=False, target=hostname,
                           error=f"Wordlist not found or empty: {_WORDLIST_PATH}")

    base_status, base_len = _get_baseline(url)
    if base_status == -1:
        return ParamResult(success=False, target=hostname,
                           error="Could not reach target URL.")

    # Separate GET baseline (same URL) from POST baseline
    post_base_status, post_base_len = base_status, base_len
    if "POST" in methods:
        try:
            r = requests.post(url, data={}, headers=_HEADERS,
                              timeout=_TIMEOUT, verify=False)
            post_base_status, post_base_len = r.status_code, len(r.content)
        except Exception:
            pass

    findings: list[ParamFinding] = []
    tested = 0

    for param in wordlist:
        if "GET" in methods:
            f = _probe_get(url, param, base_status, base_len)
            tested += 1
            if f:
                findings.append(f)

        if "POST" in methods:
            f = _probe_post(url, param, post_base_status, post_base_len)
            tested += 1
            if f:
                findings.append(f)

    return ParamResult(success=True, target=hostname,
                       findings=findings, tested=tested)
