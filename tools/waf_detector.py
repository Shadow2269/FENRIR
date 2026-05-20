"""
tools/waf_detector.py
Detects Web Application Firewalls (WAF) by analysing HTTP response headers,
status codes, and body patterns when sending crafted / malicious-looking requests.
"""
import requests
import urllib3
from dataclasses import dataclass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10


@dataclass
class WAFResult:
    success:    bool
    target:     str
    detected:   bool
    waf_name:   str   # empty string if not identified
    confidence: str   # "High" | "Medium" | "Low" | ""
    evidence:   str   # human-readable explanation of what triggered detection
    error:      str = ""


# ── Fingerprint database ──────────────────────────────────────────────────────

# (waf_name, header_key, header_value_substr)  — checked on normal requests
_HEADER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("Cloudflare",       "cf-ray",               ""),
    ("Cloudflare",       "server",                "cloudflare"),
    ("AWS WAF",          "x-amzn-requestid",      ""),
    ("AWS WAF",          "x-amz-cf-id",           ""),
    ("Sucuri",           "x-sucuri-id",           ""),
    ("Sucuri",           "server",                "sucuri"),
    ("Akamai",           "x-akamai-transformed",  ""),
    ("Akamai",           "x-check-cacheable",     ""),
    ("Imperva",          "x-iinfo",               ""),
    ("Imperva",          "x-cdn",                 "imperva"),
    ("Barracuda",        "x-barracuda-connect",   ""),
    ("F5 BIG-IP ASM",    "x-wa-info",             ""),
    ("F5 BIG-IP ASM",    "x-cnection",            ""),
    ("Fortinet",         "x-fw-server",           ""),
    ("Fortinet",         "fortigate",             ""),
    ("ModSecurity",      "server",                "mod_security"),
    ("ModSecurity",      "server",                "modsecurity"),
    ("Reblaze",          "x-reblaze-protection",  ""),
    ("Wallarm",          "x-wallarm-node",        ""),
    ("Nginx + naxsi",    "x-data-origin",         "naxsi"),
    ("Varnish",          "x-varnish",             ""),
    ("DDoS-Guard",       "ddos-guard",            ""),
    ("Netlify",          "x-nf-request-id",       ""),
    ("Fastly",           "x-served-by",           "cache-"),
    ("Fastly",           "fastly-restarts",       ""),
]

# Body patterns when WAF blocks a request (status 403/406/429/503)
_BLOCK_BODY_PATTERNS: list[tuple[str, str]] = [
    ("Cloudflare",   "Cloudflare Ray ID"),
    ("Cloudflare",   "cf-ray"),
    ("Sucuri",       "Access Denied - Sucuri Website Firewall"),
    ("Imperva",      "Incapsula incident"),
    ("AWS WAF",      "AWS WAF"),
    ("Barracuda",    "Barracuda Networks"),
    ("F5 BIG-IP",    "The requested URL was rejected"),
    ("ModSecurity",  "ModSecurity"),
    ("ModSecurity",  "Not Acceptable"),
    ("Akamai",       "Reference #"),
    ("Reblaze",      "Blocked by Reblaze"),
    ("DDoS-Guard",   "DDoS-Guard"),
    ("Generic WAF",  "Web Application Firewall"),
    ("Generic WAF",  "Your request has been blocked"),
    ("Generic WAF",  "Security Policy Violation"),
    ("Generic WAF",  "Request Rejected"),
]

# Crafted payloads that trigger WAF blocks (SQLi / XSS / path traversal mix)
_PROBE_PAYLOADS = [
    "?id=1' OR '1'='1",
    "?q=<script>alert(1)</script>",
    "?file=../../../../etc/passwd",
    "?cmd=;cat+/etc/passwd",
]


def detect_waf(target: str) -> WAFResult:
    """
    Send a normal request + crafted probes to *target* and fingerprint any WAF.

    Returns a WAFResult — detection is best-effort; false negatives are possible
    when a WAF is in transparent/stealth mode.
    """
    base = target if target.startswith(("http://", "https://")) else f"http://{target}"
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    # ── Step 1: Normal request — header fingerprinting ────────────────────────
    try:
        resp = session.get(base, timeout=_TIMEOUT, allow_redirects=True)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for waf, hdr, val_substr in _HEADER_FINGERPRINTS:
            hdr_val = headers_lower.get(hdr.lower(), "")
            if hdr_val and (not val_substr or val_substr in hdr_val):
                return WAFResult(
                    success=True, target=target, detected=True,
                    waf_name=waf, confidence="High",
                    evidence=f"Header '{hdr}: {resp.headers.get(hdr, '')}' matches {waf} fingerprint",
                )
    except requests.RequestException as exc:
        return WAFResult(success=False, target=target, detected=False,
                         waf_name="", confidence="", evidence="", error=str(exc))

    # ── Step 2: Crafted probes — block/body detection ─────────────────────────
    for payload in _PROBE_PAYLOADS:
        try:
            probe_url = base.rstrip("/") + payload
            r = session.get(probe_url, timeout=_TIMEOUT, allow_redirects=False)
            if r.status_code in (400, 403, 406, 429, 503):
                body = r.text[:3000].lower()
                for waf, pattern in _BLOCK_BODY_PATTERNS:
                    if pattern.lower() in body:
                        return WAFResult(
                            success=True, target=target, detected=True,
                            waf_name=waf, confidence="High",
                            evidence=f"Probe '{payload}' blocked (HTTP {r.status_code}); body contains '{pattern}'",
                        )
                # Blocked but no specific fingerprint
                return WAFResult(
                    success=True, target=target, detected=True,
                    waf_name="Unknown WAF", confidence="Medium",
                    evidence=f"Probe '{payload}' returned HTTP {r.status_code} — generic block detected",
                )
        except requests.RequestException:
            continue

    return WAFResult(
        success=True, target=target, detected=False,
        waf_name="", confidence="",
        evidence="No WAF signatures detected — server may use stealth mode or no WAF is present",
    )
