"""
tools/idor_tester.py
IDOR (Insecure Direct Object Reference) detector.

For every numeric ID found in URL path segments and query parameters the
scanner tries ±1, ±5, ±10, ±50, ±100 and a few random nearby values.
A significant response-length change or unexpected 2xx on a probed ID is
flagged as a potential IDOR finding.
"""
import random
import requests
import urllib3
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from security.validator import is_allowed_target
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = get_headers()
_OFFSETS = [1, 2, 5, 10, 50, 100]
_LENGTH_DIFF_THRESHOLD = 0.15   # 15 % change flags a finding
_MIN_BODY_LEN = 20              # ignore tiny "not found" pages for length math


@dataclass
class IDORFinding:
    location:        str   # "path" | "param"
    param_or_segment: str
    original_url:    str
    tested_url:      str
    original_id:     int
    tested_id:       int
    original_length: int
    tested_length:   int
    status_code:     int
    detail:          str


@dataclass
class IDORResult:
    success:  bool
    target:   str
    base_url: str
    findings: list[IDORFinding] = field(default_factory=list)
    tested:   int               = 0
    error:    str               = ""

    @property
    def vulnerable_count(self) -> int:
        return len(self.findings)


# ── helpers ───────────────────────────────────────────────────────────────────

def _fetch(url: str, auth_header: str = "") -> tuple[int, int]:
    """Return (status_code, content_length). Returns (-1, 0) on error."""
    hdrs = dict(_HEADERS)
    if auth_header:
        hdrs["Authorization"] = auth_header
    try:
        r = requests.get(url, headers=hdrs, timeout=_TIMEOUT,
                         allow_redirects=False, verify=False)
        opsec_sleep()
        return r.status_code, len(r.content)
    except Exception:
        return -1, 0


def _relative_diff(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 0.0
    return abs(a - b) / max(a, b)


def _probe_id(base_url: str, original_id: int, location: str,
              segment_idx: int | None, param_name: str | None,
              baseline_len: int, auth_header: str) -> list[IDORFinding]:
    findings: list[IDORFinding] = []
    offsets = list(_OFFSETS) + [random.randint(200, 999)]

    for off in offsets:
        for candidate_id in {original_id + off, original_id - off}:
            if candidate_id < 0:
                continue
            if location == "path":
                parsed = urlparse(base_url)
                parts  = parsed.path.split("/")
                parts[segment_idx] = str(candidate_id)   # type: ignore[index]
                tested_url = urlunparse(parsed._replace(path="/".join(parts)))
            else:
                parsed = urlparse(base_url)
                qs     = parse_qs(parsed.query, keep_blank_values=True)
                qs[param_name] = [str(candidate_id)]     # type: ignore[index]
                tested_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            status, length = _fetch(tested_url, auth_header)
            if status == -1:
                continue

            diff = _relative_diff(baseline_len, length)
            if (
                baseline_len >= _MIN_BODY_LEN
                and length   >= _MIN_BODY_LEN
                and diff     >= _LENGTH_DIFF_THRESHOLD
                and status in (200, 201, 202, 206)
            ):
                detail = (
                    f"ID {original_id} → {candidate_id}: "
                    f"length {baseline_len} → {length} "
                    f"({diff:.0%} diff, HTTP {status})"
                )
                findings.append(IDORFinding(
                    location=location,
                    param_or_segment=param_name or str(segment_idx),
                    original_url=base_url,
                    tested_url=tested_url,
                    original_id=original_id,
                    tested_id=candidate_id,
                    original_length=baseline_len,
                    tested_length=length,
                    status_code=status,
                    detail=detail,
                ))
                break  # one finding per offset direction is enough

    return findings


# ── public API ────────────────────────────────────────────────────────────────

def test_idor(url: str, auth_header: str = "",
              confirmed: bool = False) -> IDORResult:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed   = urlparse(url)
    hostname = parsed.hostname or url

    ok, reason = is_allowed_target(hostname), ""
    if not ok and not confirmed:
        return IDORResult(success=False, target=hostname, base_url=url,
                          error=f"Target not in allowlist: {hostname}")

    baseline_status, baseline_len = _fetch(url, auth_header)
    if baseline_status == -1:
        return IDORResult(success=False, target=hostname, base_url=url,
                          error="Could not reach target URL.")

    findings: list[IDORFinding] = []
    tested = 0

    # ── Probe path segments ───────────────────────────────────────────────────
    parts = parsed.path.split("/")
    for idx, segment in enumerate(parts):
        if segment.isdigit():
            base_id = int(segment)
            tested += 1
            findings += _probe_id(url, base_id, "path", idx, None,
                                  baseline_len, auth_header)

    # ── Probe query parameters ────────────────────────────────────────────────
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in qs.items():
        if values and values[0].isdigit():
            base_id = int(values[0])
            tested += 1
            findings += _probe_id(url, base_id, "param", None, name,
                                  baseline_len, auth_header)

    # Deduplicate: keep first finding per (location, param, tested_id)
    seen: set[tuple] = set()
    deduped: list[IDORFinding] = []
    for f in findings:
        key = (f.location, f.param_or_segment, f.tested_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return IDORResult(
        success=True,
        target=hostname,
        base_url=url,
        findings=deduped,
        tested=tested,
    )
