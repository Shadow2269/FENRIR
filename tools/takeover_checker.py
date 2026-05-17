"""
tools/takeover_checker.py
Subdomain takeover detection via CNAME resolution + HTTP fingerprinting.

A subdomain takeover occurs when a CNAME record points to an external service
(e.g. GitHub Pages, Heroku, AWS S3) that has been decommissioned but the DNS
record was never removed. An attacker can claim the service and serve content
on the victim's subdomain.
"""
import socket
import requests
from dataclasses import dataclass, field
from logger import warn, log


# ── Fingerprint database ──────────────────────────────────────────────────────
# Each entry: (cname_keyword, service_name, body_indicator, confidence)
# confidence: "High" = indicator is very specific / "Medium" = plausible

_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    # GitHub Pages
    ("github.io",           "GitHub Pages",     "There isn't a GitHub Pages site here",   "High"),
    ("github.io",           "GitHub Pages",     "For root URLs (like http://example.com/)", "High"),
    # Heroku
    ("herokuapp.com",       "Heroku",           "No such app",                            "High"),
    ("herokudns.com",       "Heroku",           "No such app",                            "High"),
    # AWS S3
    ("s3.amazonaws.com",    "AWS S3",           "NoSuchBucket",                           "High"),
    ("s3-website",          "AWS S3",           "NoSuchBucket",                           "High"),
    ("s3-website",          "AWS S3",           "The specified bucket does not exist",     "High"),
    # Fastly
    ("fastly.net",          "Fastly",           "Fastly error: unknown domain",            "High"),
    # Shopify
    ("myshopify.com",       "Shopify",          "Sorry, this shop is currently unavailable", "High"),
    # Zendesk
    ("zendesk.com",         "Zendesk",          "Help Center Closed",                     "High"),
    # Azure / Microsoft
    ("azurewebsites.net",   "Azure Web Apps",   "404 Web Site not found",                 "High"),
    ("cloudapp.net",        "Azure",            "404 Not Found",                          "Medium"),
    ("trafficmanager.net",  "Azure Traffic Mgr","404 Not Found",                          "Medium"),
    # Netlify
    ("netlify.app",         "Netlify",          "Not Found - Request ID",                 "High"),
    ("netlify.com",         "Netlify",          "Not Found - Request ID",                 "High"),
    # Squarespace
    ("squarespace.com",     "Squarespace",      "No Such Account",                        "High"),
    # Ghost
    ("ghost.io",            "Ghost",            "Domain Error",                           "High"),
    # Tumblr
    ("tumblr.com",          "Tumblr",           "There's nothing here",                   "High"),
    # Surge.sh
    ("surge.sh",            "Surge",            "project not found",                      "High"),
    # Readme.io
    ("readme.io",           "ReadMe",           "Project doesnt exist",                   "High"),
    # Webflow
    ("webflow.io",          "Webflow",          "The page you are looking for doesn",      "High"),
    # Pantheon
    ("pantheonsite.io",     "Pantheon",         "The gods are wise",                      "High"),
    # Cargo
    ("cargocollective.com", "Cargo",            "404 Not Found",                          "Medium"),
    # UserVoice
    ("uservoice.com",       "UserVoice",        "This UserVoice subdomain is currently available", "High"),
    # Intercom
    ("custom.intercom.help","Intercom",         "This page is reserved",                  "High"),
    # HubSpot
    ("hubspot.net",         "HubSpot",          "Domain not found",                       "High"),
    # Wordpress.com
    ("wordpress.com",       "WordPress.com",    "Do you want to register",                "High"),
    # Unbounce
    ("unbouncepages.com",   "Unbounce",         "The requested URL was not found",         "Medium"),
    # Tilda
    ("tilda.ws",            "Tilda",            "Please renew your subscription",          "High"),
    # Bitbucket
    ("bitbucket.io",        "Bitbucket",        "Repository not found",                   "High"),
    # Desk.com (Salesforce)
    ("desk.com",            "Desk.com",         "Please try again or try Desk.com",        "High"),
    # Helpjuice
    ("helpjuice.com",       "Helpjuice",        "We could not find what you're looking for", "High"),
    # Feedpress
    ("feedpress.me",        "Feedpress",        "The feed has not been found",             "High"),
    # Strikingly
    ("strikinglydns.com",   "Strikingly",       "But if you're looking to build your own website", "High"),
]


@dataclass
class TakeoverFinding:
    subdomain: str
    cname: str
    service: str
    indicator: str
    confidence: str   # High | Medium


@dataclass
class TakeoverResult:
    success: bool
    target: str
    checked: int = 0
    vulnerable: list[TakeoverFinding] = field(default_factory=list)
    error: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.vulnerable) > 0

    @property
    def high_confidence(self) -> list[TakeoverFinding]:
        return [f for f in self.vulnerable if f.confidence == "High"]


def check_takeover(subdomains: list[str], target_domain: str = "") -> TakeoverResult:
    """
    Check a list of subdomains for takeover vulnerabilities.

    For each subdomain:
      1. Resolve CNAME chain
      2. Match CNAME against fingerprint DB
      3. If match: HTTP request to confirm indicator in response body

    Args:
        subdomains:    List of subdomain strings to check.
        target_domain: Parent domain (for result labelling only).

    Returns:
        TakeoverResult with all vulnerable findings.
    """
    result = TakeoverResult(success=True, target=target_domain or "multiple")

    for subdomain in subdomains:
        result.checked += 1
        cname = _resolve_cname(subdomain)
        if not cname:
            continue

        match = _match_fingerprint(cname)
        if not match:
            continue

        service, indicator, confidence = match
        if _confirm_via_http(subdomain, indicator):
            result.vulnerable.append(TakeoverFinding(
                subdomain=subdomain,
                cname=cname,
                service=service,
                indicator=indicator,
                confidence=confidence,
            ))
            log(f"[TAKEOVER] {subdomain} -> {cname} ({service}) [{confidence}]")

    return result


def _resolve_cname(subdomain: str) -> str:
    """
    Resolve CNAME chain for subdomain using dnspython if available,
    falling back to socket.getaddrinfo for simple resolution.
    Returns the final CNAME target or empty string if none found.
    """
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            return str(answers[0].target).rstrip(".")
        except Exception:
            return ""
    except ImportError:
        # dnspython not installed — skip CNAME check, just check hostname
        try:
            socket.gethostbyname(subdomain)
            return subdomain  # No CNAME resolution but host resolves
        except Exception:
            return ""


def _match_fingerprint(cname: str) -> tuple[str, str, str] | None:
    """Return (service, indicator, confidence) if cname matches a fingerprint."""
    cname_lower = cname.lower()
    for cname_kw, service, indicator, confidence in _FINGERPRINTS:
        if cname_kw in cname_lower:
            return service, indicator, confidence
    return None


def _confirm_via_http(subdomain: str, indicator: str) -> bool:
    """
    Send an HTTP request to subdomain and check if the takeover indicator
    appears in the response body. Tries HTTPS first, then HTTP.
    """
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (FENRIR security scanner)"},
                verify=False,
            )
            if indicator.lower() in resp.text.lower():
                return True
        except Exception:
            continue
    return False
