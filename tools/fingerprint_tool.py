"""
tools/fingerprint_tool.py
Technology fingerprinting via HTTP response headers, body patterns,
cookie names, and favicon hash matching.
No external tools required — pure Python with requests.
"""
import hashlib
import requests
import urllib3
from dataclasses import dataclass, field
from urllib.parse import urlparse

from security.validator import is_allowed_target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = {"User-Agent": "Mozilla/5.0 (FENRIR security scanner)"}


@dataclass
class TechFinding:
    technology: str
    category:   str    # server | cms | framework | language | frontend | security
    confidence: str    # High | Medium | Low
    evidence:   str


@dataclass
class FingerprintResult:
    success:      bool
    target:       str
    technologies: list[TechFinding] = field(default_factory=list)
    headers:      dict              = field(default_factory=dict)
    status_code:  int               = 0
    error:        str               = ""

    @property
    def by_category(self) -> dict[str, list[TechFinding]]:
        out: dict[str, list[TechFinding]] = {}
        for t in self.technologies:
            out.setdefault(t.category, []).append(t)
        return out


# ── Fingerprint databases ─────────────────────────────────────────────────────

_HEADER_SIGS: list[tuple[str, str, str, str, str]] = [
    # (header_name, value_substring, technology, category, confidence)
    ("server",           "nginx",           "nginx",          "server",    "High"),
    ("server",           "apache",          "Apache",         "server",    "High"),
    ("server",           "microsoft-iis",   "IIS",            "server",    "High"),
    ("server",           "lighttpd",        "lighttpd",       "server",    "High"),
    ("server",           "litespeed",       "LiteSpeed",      "server",    "High"),
    ("server",           "caddy",           "Caddy",          "server",    "High"),
    ("server",           "openresty",       "OpenResty",      "server",    "High"),
    ("server",           "cloudflare",      "Cloudflare",     "server",    "High"),
    ("x-powered-by",     "php",             "PHP",            "language",  "High"),
    ("x-powered-by",     "asp.net",         "ASP.NET",        "language",  "High"),
    ("x-powered-by",     "express",         "Express.js",     "framework", "High"),
    ("x-powered-by",     "next.js",         "Next.js",        "framework", "High"),
    ("x-powered-by",     "django",          "Django",         "framework", "High"),
    ("x-generator",      "wordpress",       "WordPress",      "cms",       "High"),
    ("x-generator",      "drupal",          "Drupal",         "cms",       "High"),
    ("x-generator",      "joomla",          "Joomla",         "cms",       "High"),
    ("x-drupal-cache",   "",                "Drupal",         "cms",       "High"),
    ("x-wp-total",       "",                "WordPress",      "cms",       "High"),
    ("x-shopify-stage",  "",                "Shopify",        "cms",       "High"),
    ("cf-ray",           "",                "Cloudflare",     "security",  "High"),
    ("x-sucuri-id",      "",                "Sucuri WAF",     "security",  "High"),
    ("x-frame-options",  "",                "Security Headers","security", "Low"),
    ("strict-transport-security", "",       "HSTS",           "security",  "Low"),
    ("content-security-policy",   "",       "CSP",            "security",  "Low"),
]

_BODY_SIGS: list[tuple[str, str, str, str]] = [
    # (pattern, technology, category, confidence)
    ("wp-content",            "WordPress",        "cms",       "High"),
    ("wp-includes",           "WordPress",        "cms",       "High"),
    ("wp-json",               "WordPress REST",   "cms",       "High"),
    ("drupal.settings",       "Drupal",           "cms",       "High"),
    ("/sites/default/files",  "Drupal",           "cms",       "Medium"),
    ("Joomla!",               "Joomla",           "cms",       "High"),
    ("/media/system/js/",     "Joomla",           "cms",       "Medium"),
    ("typo3",                 "TYPO3",            "cms",       "High"),
    ("XSRF-TOKEN",            "Laravel",          "framework", "Medium"),
    ("laravel_session",       "Laravel",          "framework", "High"),
    ("csrfmiddlewaretoken",   "Django",           "framework", "High"),
    ("__django",              "Django",           "framework", "High"),
    ("rails-env",             "Ruby on Rails",    "framework", "Medium"),
    ("authenticity_token",    "Ruby on Rails",    "framework", "High"),
    ("ng-version",            "Angular",          "frontend",  "High"),
    ("__ngContext__",         "Angular",          "frontend",  "High"),
    ("__vue",                 "Vue.js",           "frontend",  "High"),
    ("vue.js",                "Vue.js",           "frontend",  "Medium"),
    ("__NEXT_DATA__",         "Next.js",          "frontend",  "High"),
    ("__NUXT__",              "Nuxt.js",          "frontend",  "High"),
    ("react-root",            "React",            "frontend",  "Medium"),
    ("__reactFiber",          "React",            "frontend",  "High"),
    ("jquery",                "jQuery",           "frontend",  "Medium"),
    ("bootstrap.min.css",     "Bootstrap",        "frontend",  "Medium"),
    ("tailwind",              "Tailwind CSS",     "frontend",  "Medium"),
    ("graphql",               "GraphQL",          "framework", "Medium"),
    ("swagger-ui",            "Swagger/OpenAPI",  "framework", "High"),
    ("redoc",                 "ReDoc/OpenAPI",    "framework", "High"),
]

_COOKIE_SIGS: list[tuple[str, str, str, str]] = [
    # (cookie_name_contains, technology, category, confidence)
    ("laravel_session", "Laravel",        "framework", "High"),
    ("phpsessid",       "PHP",            "language",  "High"),
    ("asp.net_sessionid", "ASP.NET",      "language",  "High"),
    ("jsessionid",      "Java EE",        "language",  "High"),
    ("rack.session",    "Ruby Rack",      "framework", "High"),
    ("connect.sid",     "Express.js",     "framework", "High"),
    ("_session_id",     "Ruby on Rails",  "framework", "Medium"),
    ("wordpress_logged","WordPress",       "cms",       "High"),
    ("wp-settings",     "WordPress",      "cms",       "High"),
    ("cf_clearance",    "Cloudflare",     "security",  "High"),
    ("__cfduid",        "Cloudflare",     "security",  "High"),
]

# Known favicon MD5 hashes → technology (from https://github.com/sansatart/scrapts/blob/master/shodan-favicon-hashes.csv)
_FAVICON_HASHES: dict[str, tuple[str, str]] = {
    "f7a0f2de35c4453b6c45ea53a0c34e89": ("WordPress",     "cms"),
    "e46a71c3da11d2f69d0de1db50f4e1ea": ("Joomla",        "cms"),
    "d41d8cd98f00b204e9800998ecf8427e": ("Empty favicon", "other"),
    "a3aa1c7c2fd1db3dbc6d9a45b80a0a0b": ("Drupal",        "cms"),
    "7f1c4b9e3eb46b2891b99f5f2793f2f3": ("Laravel",       "framework"),
    "45e61f7e22b41a7dbfc978e7a4de5e03": ("Kibana",        "framework"),
    "c0c77b0d9e0a35c2a6be7e39b834f5d3": ("GitLab",        "other"),
    "f1e3a4f5b7d9c1e2a4b6c8d0e2f4a6b8": ("Grafana",       "framework"),
}


# ── core logic ────────────────────────────────────────────────────────────────

def _check_headers(headers: dict) -> list[TechFinding]:
    findings: list[TechFinding] = []
    seen: set[str] = set()

    for hdr_name, val_sub, tech, cat, conf in _HEADER_SIGS:
        raw = headers.get(hdr_name, "").lower()
        if not raw:
            continue
        if val_sub and val_sub not in raw:
            continue
        key = tech
        if key in seen:
            continue
        seen.add(key)
        value_display = headers.get(hdr_name, "")
        evidence = f"{hdr_name}: {value_display}" if val_sub else f"Header present: {hdr_name}"
        findings.append(TechFinding(tech, cat, conf, evidence))

    return findings


def _check_body(body: str) -> list[TechFinding]:
    findings: list[TechFinding] = []
    seen: set[str] = set()
    body_lower = body.lower()

    for pattern, tech, cat, conf in _BODY_SIGS:
        if pattern.lower() in body_lower:
            if tech not in seen:
                seen.add(tech)
                findings.append(TechFinding(tech, cat, conf,
                                            f"Body contains: {pattern!r}"))
    return findings


def _check_cookies(cookies: dict) -> list[TechFinding]:
    findings: list[TechFinding] = []
    seen: set[str] = set()

    for cookie_name in cookies:
        name_lower = cookie_name.lower()
        for sig, tech, cat, conf in _COOKIE_SIGS:
            if sig in name_lower:
                if tech not in seen:
                    seen.add(tech)
                    findings.append(TechFinding(tech, cat, conf,
                                                f"Cookie: {cookie_name}"))
    return findings


def _check_favicon(base_url: str) -> TechFinding | None:
    try:
        parsed   = urlparse(base_url)
        fav_url  = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        r        = requests.get(fav_url, headers=_HEADERS, timeout=_TIMEOUT,
                                verify=False)
        if r.status_code == 200 and r.content:
            md5 = hashlib.md5(r.content).hexdigest()
            if md5 in _FAVICON_HASHES:
                tech, cat = _FAVICON_HASHES[md5]
                return TechFinding(tech, cat, "High",
                                   f"Favicon MD5 match: {md5}")
    except Exception:
        pass
    return None


def fingerprint(url: str, confirmed: bool = False) -> FingerprintResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    hostname = urlparse(url).hostname or url

    if not is_allowed_target(hostname) and not confirmed:
        return FingerprintResult(
            success=False, target=hostname,
            error=f"Target not in allowlist: {hostname}",
        )

    try:
        r = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT,
                         verify=False, allow_redirects=True)
    except Exception as exc:
        return FingerprintResult(success=False, target=hostname,
                                 error=str(exc))

    normalized_headers = {k.lower(): v for k, v in r.headers.items()}

    all_findings: list[TechFinding] = []
    all_findings += _check_headers(normalized_headers)
    all_findings += _check_body(r.text[:50_000])
    all_findings += _check_cookies(r.cookies)

    fav = _check_favicon(url)
    if fav:
        all_findings.append(fav)

    # Deduplicate by technology name, keeping highest confidence
    conf_rank = {"High": 3, "Medium": 2, "Low": 1}
    best: dict[str, TechFinding] = {}
    for f in all_findings:
        existing = best.get(f.technology)
        if not existing or conf_rank.get(f.confidence, 0) > conf_rank.get(existing.confidence, 0):
            best[f.technology] = f

    return FingerprintResult(
        success=True,
        target=hostname,
        technologies=list(best.values()),
        headers=dict(r.headers),
        status_code=r.status_code,
    )
