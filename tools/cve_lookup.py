"""
tools/cve_lookup.py
Queries the NVD (National Vulnerability Database) API for CVEs
based on software names and versions found in an nmap scan.

Lookup strategy (per service):
  1. Known CPE map  → hardcoded product→CPE for the 40+ most common nmap products
  2. CPE dict API   → fuzzy lookup for unknown products (requires ≥2 token overlap)
  3. CVE query      → fetch CVEs via CPE with version-range metadata
  4. Version filter → discard CVEs whose affected range excludes the scanned version
  5. Confidence tag → "verified" if range data confirmed, "unverified" if not
  6. Keyword fallback → last resort when CPE lookup fails (all results = unverified)
"""

import re
import time
import requests
from dataclasses import dataclass, field
from typing import Optional
from logger import log, warn

try:
    from packaging.version import Version as PkgVersion, InvalidVersion
    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
REQUEST_DELAY = 6.5   # seconds between requests (safe under the 5/30s limit)

# ── Known product → NVD CPE base map ─────────────────────────────────────────
# Keys are lowercase nmap product strings (or substrings thereof).
# Values are the authoritative NVD CPE 2.3 base (no version field).
# When matched, the API CPE-dictionary call is skipped entirely → faster,
# no rate-limit hit, and the correct CPE is guaranteed.
_KNOWN_CPE_MAP: dict[str, str] = {
    # Web servers
    "nginx":                          "cpe:2.3:a:nginx:nginx",
    "apache httpd":                   "cpe:2.3:a:apache:http_server",
    "apache":                         "cpe:2.3:a:apache:http_server",
    "lighttpd":                       "cpe:2.3:a:lighttpd:lighttpd",
    "microsoft iis":                  "cpe:2.3:a:microsoft:internet_information_services",
    "iis":                            "cpe:2.3:a:microsoft:internet_information_services",
    # SSH / TLS
    "openssh":                        "cpe:2.3:a:openbsd:openssh",
    "openssl":                        "cpe:2.3:a:openssl:openssl",
    "libssl":                         "cpe:2.3:a:openssl:openssl",
    # FTP
    "vsftpd":                         "cpe:2.3:a:beasts:vsftpd",
    "proftpd":                        "cpe:2.3:a:proftpd:proftpd",
    "pure-ftpd":                      "cpe:2.3:a:pureftpd:pure-ftpd",
    "filezilla":                      "cpe:2.3:a:filezilla-project:filezilla_server",
    # Mail
    "exim":                           "cpe:2.3:a:exim:exim",
    "postfix":                        "cpe:2.3:a:wietse_venema:postfix",
    "sendmail":                       "cpe:2.3:a:sendmail:sendmail",
    "dovecot":                        "cpe:2.3:a:dovecot:dovecot",
    # Databases
    "mysql":                          "cpe:2.3:a:mysql:mysql",
    "mariadb":                        "cpe:2.3:a:mariadb:mariadb",
    "postgresql":                     "cpe:2.3:a:postgresql:postgresql",
    "redis":                          "cpe:2.3:a:redis:redis",
    "mongodb":                        "cpe:2.3:a:mongodb:mongodb",
    "elasticsearch":                  "cpe:2.3:a:elastic:elasticsearch",
    "memcached":                      "cpe:2.3:a:memcached:memcached",
    "couchdb":                        "cpe:2.3:a:apache:couchdb",
    # App servers / runtimes
    "apache tomcat":                  "cpe:2.3:a:apache:tomcat",
    "tomcat":                         "cpe:2.3:a:apache:tomcat",
    "jetty":                          "cpe:2.3:a:eclipse:jetty",
    "jboss":                          "cpe:2.3:a:redhat:jboss_enterprise_application_platform",
    "wildfly":                        "cpe:2.3:a:redhat:wildfly",
    "php":                            "cpe:2.3:a:php:php",
    "node.js":                        "cpe:2.3:a:nodejs:node.js",
    "nodejs":                         "cpe:2.3:a:nodejs:node.js",
    # CMS
    "wordpress":                      "cpe:2.3:a:wordpress:wordpress",
    "drupal":                         "cpe:2.3:a:drupal:drupal",
    "joomla":                         "cpe:2.3:a:joomla:joomla",
    # DNS
    "bind":                           "cpe:2.3:a:isc:bind",
    "named":                          "cpe:2.3:a:isc:bind",
    "unbound":                        "cpe:2.3:a:nlnetlabs:unbound",
    "powerdns":                       "cpe:2.3:a:powerdns:authoritative",
    # Proxy / network
    "squid":                          "cpe:2.3:a:squid-cache:squid",
    "haproxy":                        "cpe:2.3:a:haproxy:haproxy",
    "varnish":                        "cpe:2.3:a:varnish_cache_project:varnish_cache",
    # SMB / Windows
    "samba":                          "cpe:2.3:a:samba:samba",
    # VPN / remote
    "openvpn":                        "cpe:2.3:a:openvpn:openvpn",
    "openconnect":                    "cpe:2.3:a:infradead:openconnect",
    # Misc
    "zookeeper":                      "cpe:2.3:a:apache:zookeeper",
    "rabbitmq":                       "cpe:2.3:a:pivotal_software:rabbitmq",
    "kafka":                          "cpe:2.3:a:apache:kafka",
}

# Suffixes nmap appends after the version that must be stripped before comparison
_OS_SUFFIX_RE = re.compile(
    r"\s+(Ubuntu|Debian|Fedora|CentOS|RHEL|Red\s*Hat|Alpine|Arch|Gentoo|Kali|Raspbian)"
    r"[\w/.+-]*",
    re.IGNORECASE,
)


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    published: str
    url: str
    confidence: str = "verified"  # "verified" | "unverified"


@dataclass
class ServiceCVEResult:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    cves: list[CVEEntry] = field(default_factory=list)
    version_is_estimate: bool = False  # True when version came from behavioral fingerprinting

    @property
    def max_cvss(self) -> float:
        return max((c.cvss_score for c in self.cves), default=0.0)

    @property
    def critical_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.cvss_severity == "Critical"]

    @property
    def high_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.cvss_severity == "High"]

    @property
    def verified_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.confidence == "verified"]

    @property
    def unverified_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.confidence == "unverified"]


# ── nmap output parser ────────────────────────────────────────────────────────

def parse_nmap_services(nmap_output: str) -> list[dict]:
    """
    Extract service/version info from nmap -sV output.

    Returns a list of dicts:
      { port, protocol, state, service, product, version }
    """
    services = []
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s+(.*?)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(nmap_output):
        port, proto, state, service, rest = match.groups()
        product, version = _split_product_version(rest)
        if product:
            services.append({
                "port": int(port),
                "protocol": proto,
                "state": state,
                "service": service,
                "product": product.strip(),
                "version": version.strip(),
            })
    return services


def _split_product_version(text: str) -> tuple[str, str]:
    """Split 'Apache httpd 2.4.49 ((Unix))' into ('Apache httpd', '2.4.49').

    Also strips OS/distro suffixes nmap appends after the version, e.g.:
      'OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)'
      → product='OpenSSH', version='8.2p1'
    """
    text = re.sub(r"\(.*?\)", "", text)   # strip (Ubuntu), ((Unix)), etc.
    text = _OS_SUFFIX_RE.sub("", text)    # strip bare 'Ubuntu 4ubuntu0.5' etc.
    text = text.strip()
    version_match = re.search(r"\b(\d[\d.]+\w*)\b", text)
    if version_match:
        version = version_match.group(1)
        product = text[:version_match.start()].strip()
        return product, version
    return text, ""


# ── version comparison ────────────────────────────────────────────────────────

def _parse_version(v: str):
    """Parse version string into a comparable object."""
    if not v:
        return None
    if _HAS_PACKAGING:
        try:
            return PkgVersion(v)
        except InvalidVersion:
            pass
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else None


def _version_in_range(version: str, cpe_match: dict) -> bool:
    """
    Return True if *version* falls within the affected range of a CPE match entry.
    Conservative: returns True when no range info is present (include unknown cases).
    """
    if not version:
        return True

    v = _parse_version(version)
    if v is None:
        return True

    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc   = cpe_match.get("versionEndIncluding")
    end_exc   = cpe_match.get("versionEndExcluding")

    # No range boundaries → check if criteria CPE contains an exact version match
    if not any([start_inc, start_exc, end_inc, end_exc]):
        criteria = cpe_match.get("criteria", "")
        parts = criteria.split(":")
        # part index 5 is the version field in CPE 2.3
        if len(parts) > 5 and parts[5] not in ("*", "-", ""):
            return parts[5] == version
        return True  # wildcard version in criteria → include conservatively

    if start_inc:
        s = _parse_version(start_inc)
        if s is not None and v < s:
            return False

    if start_exc:
        s = _parse_version(start_exc)
        if s is not None and v <= s:
            return False

    if end_inc:
        e = _parse_version(end_inc)
        if e is not None and v > e:
            return False

    if end_exc:
        e = _parse_version(end_exc)
        if e is not None and v >= e:
            return False

    return True


def _cve_affects_version(cve_item: dict, version: str) -> tuple[bool, bool]:
    """Return (matches, is_verified).

    is_verified=True only when NVD version-range data explicitly confirms the match
    (range boundaries or exact CPE version field). is_verified=False when the match
    is conservative (no configuration data, or wildcard CPE version field).
    """
    if not version:
        return True, False

    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        return True, False  # no config data → conservative include, not verified

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                if not _version_in_range(version, cpe_match):
                    continue
                # Determine if this is an explicit range/version match
                has_range = any([
                    cpe_match.get("versionStartIncluding"),
                    cpe_match.get("versionStartExcluding"),
                    cpe_match.get("versionEndIncluding"),
                    cpe_match.get("versionEndExcluding"),
                ])
                if has_range:
                    return True, True
                # Exact version in CPE criteria (not wildcard)
                parts = cpe_match.get("criteria", "").split(":")
                if len(parts) > 5 and parts[5] not in ("*", "-", ""):
                    return True, True
                return True, False  # wildcard CPE version → conservative
    return False, False


# ── rate-limited NVD API helper ───────────────────────────────────────────────

def _api_get(url: str, params: dict, api_key: str) -> Optional[dict]:
    """
    Single NVD API GET with rate-limit sleep after every call, success or failure.
    Returns parsed JSON dict or None on error.
    """
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        warn(f"NVD API error ({url}): {exc}")
        return None
    finally:
        time.sleep(REQUEST_DELAY)


# ── CPE dictionary lookup ─────────────────────────────────────────────────────

def _find_cpe_base(product: str, api_key: str) -> Optional[str]:
    """
    Return the NVD CPE 2.3 base string for *product* (no version field).

    Strategy:
      1. Check _KNOWN_CPE_MAP by exact lowercase key — no API call, guaranteed correct.
      2. Check _KNOWN_CPE_MAP by substring — handles 'nginx http server' → nginx entry.
      3. Fall back to NVD CPE dictionary API with fuzzy token scoring.
    """
    key = product.lower().strip()

    # 1. Exact match
    if key in _KNOWN_CPE_MAP:
        log(f"    CPE: known map hit for '{product}'")
        return _KNOWN_CPE_MAP[key]

    # 2. Substring match (e.g. nmap reports 'nginx http server' → key 'nginx' is in it)
    for known_key, cpe in _KNOWN_CPE_MAP.items():
        if known_key in key:
            log(f"    CPE: known map partial hit '{known_key}' for '{product}'")
            return cpe

    # 3. NVD CPE dictionary API (costs one REQUEST_DELAY sleep)
    data = _api_get(NVD_CPE_API_URL, {"keywordSearch": product, "resultsPerPage": 10}, api_key)
    if not data:
        return None

    product_tokens = set(re.findall(r"\w+", key))
    best_cpe: Optional[str] = None
    best_score = 0

    for p in data.get("products", []):
        cpe_name = p.get("cpe", {}).get("cpeName", "")
        if not cpe_name.startswith("cpe:2.3:a:"):
            continue
        parts = cpe_name.split(":")
        if len(parts) < 6:
            continue

        vendor_tokens = set(re.findall(r"\w+", parts[3].replace("_", " ").replace("-", " ")))
        prod_tokens   = set(re.findall(r"\w+", parts[4].replace("_", " ").replace("-", " ")))
        score = len(product_tokens & (vendor_tokens | prod_tokens))

        if score > best_score:
            best_score = score
            best_cpe = f"cpe:2.3:a:{parts[3]}:{parts[4]}"

    # Require at least 2 matching tokens to avoid wrong CPE assignments
    return best_cpe if best_score >= 2 else None


# ── CVE fetchers ──────────────────────────────────────────────────────────────

def _fetch_by_cpe(cpe_base: str, api_key: str) -> list[dict]:
    """Fetch all CVE items for a given base CPE (wildcard version)."""
    cpe_query = f"{cpe_base}:*:*:*:*:*:*:*:*"
    data = _api_get(NVD_CVE_API_URL, {"cpeName": cpe_query, "resultsPerPage": 100}, api_key)
    return data.get("vulnerabilities", []) if data else []


def _fetch_by_keyword(keyword: str, api_key: str) -> list[dict]:
    """Fetch CVE items via full-text keyword search (fallback)."""
    data = _api_get(NVD_CVE_API_URL, {"keywordSearch": keyword, "resultsPerPage": 50}, api_key)
    return data.get("vulnerabilities", []) if data else []


# ── entry builder + CVSS ──────────────────────────────────────────────────────

def _build_cve_entry(item: dict) -> Optional[CVEEntry]:
    """Convert a raw NVD vulnerability item to a CVEEntry."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    descs = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descs if d.get("lang") == "en"),
        "No description available.",
    )
    score, severity, vector = _extract_cvss(cve)
    published = cve.get("published", "")[:10]

    return CVEEntry(
        cve_id=cve_id,
        description=description[:300],
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        published=published,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    )


def _extract_cvss(cve: dict) -> tuple[float, str, str]:
    """Extract the best available CVSS score (prefers v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score = float(m.get("baseScore", 0.0))
            severity = m.get("baseSeverity", _score_to_severity(score))
            vector = m.get("vectorString", "")
            return score, severity.capitalize(), vector
    return 0.0, "Unknown", ""


def _score_to_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ── main lookup entry point ───────────────────────────────────────────────────

def lookup_cves(
    keyword: str,
    product: str = "",
    version: str = "",
    max_results: int = 10,
    api_key: str = "",
) -> list[CVEEntry]:
    """
    Look up CVEs for a product/version using a two-phase strategy:
      Phase 1 — CPE-based:  find base CPE → query CVEs → filter by version range
      Phase 2 — Keyword:    fallback full-text search  → filter by version range

    Returns an empty list when *version* is unknown — without a version we cannot
    determine which CVEs apply, so any result would be an unverifiable false positive.

    Returns up to *max_results* entries sorted by verified first, then CVSS descending.
    """
    if not version:
        warn(f"    Skipping CVE lookup for '{product}' — no version number detected.")
        return []

    raw_items: list[dict] = []
    used_cpe = False

    if product and version:
        cpe_base = _find_cpe_base(product, api_key)
        if cpe_base:
            log(f"    CPE: {cpe_base} — querying CVEs …")
            raw_items = _fetch_by_cpe(cpe_base, api_key)
            used_cpe = True

    if not raw_items:
        if used_cpe:
            log("    CPE query returned nothing — falling back to keyword search …")
        raw_items = _fetch_by_keyword(keyword, api_key)

    # Version-range filtering with confidence tracking
    verified_items: list[dict] = []
    unverified_items: list[dict] = []

    if version and raw_items:
        for item in raw_items:
            matches, is_verified = _cve_affects_version(item, version)
            if matches:
                if is_verified and used_cpe:
                    verified_items.append(item)
                else:
                    unverified_items.append(item)
        # Keep originals as unverified if filtering removed everything
        if not verified_items and not unverified_items:
            unverified_items = raw_items
    else:
        unverified_items = raw_items

    # Keyword-fallback items are always unverified regardless of version check
    if not used_cpe:
        unverified_items = verified_items + unverified_items
        verified_items = []

    entries: list[CVEEntry] = []
    for item in verified_items:
        e = _build_cve_entry(item)
        if e:
            e.confidence = "verified"
            entries.append(e)
    for item in unverified_items:
        e = _build_cve_entry(item)
        if e:
            e.confidence = "unverified"
            entries.append(e)

    # Verified CVEs first, then by CVSS descending
    entries.sort(key=lambda e: (e.confidence == "verified", e.cvss_score), reverse=True)
    return entries[:max_results]


# ── main entry point for nmap integration ────────────────────────────────────

def run_cve_lookup(
    nmap_output: str,
    max_cves_per_service: int = 10,
    api_key: str = "",
) -> list[ServiceCVEResult]:
    """
    Parse nmap output, look up CVEs for each discovered service,
    and return a list of ServiceCVEResult objects.

    Each service triggers up to 2 NVD API calls (CPE + CVE lookup),
    each separated by REQUEST_DELAY to stay within NVD rate limits.
    """
    services = parse_nmap_services(nmap_output)

    if not services:
        warn("No versioned services found in nmap output — nothing to look up.")
        return []

    log(f"CVE lookup: found {len(services)} service(s) — querying NVD API …")
    results = []

    no_version_count = 0
    for svc in services:
        if not svc["product"]:
            continue

        if not svc["version"]:
            warn(f"  [{svc['port']}/{svc['protocol']}] {svc['product']} — "
                 "version hidden by server, CVE lookup skipped")
            no_version_count += 1
            results.append(ServiceCVEResult(
                port=svc["port"],
                protocol=svc["protocol"],
                service=svc["service"],
                product=svc["product"],
                version="",
                cves=[],
            ))
            continue

        keyword = f"{svc['product']} {svc['version']}".strip()
        log(f"  [{svc['port']}/{svc['protocol']}] {keyword}")
        cves = lookup_cves(
            keyword=keyword,
            product=svc["product"],
            version=svc["version"],
            max_results=max_cves_per_service,
            api_key=api_key,
        )

        results.append(ServiceCVEResult(
            port=svc["port"],
            protocol=svc["protocol"],
            service=svc["service"],
            product=svc["product"],
            version=svc["version"],
            cves=cves,
        ))

    total_cves = sum(len(r.cves) for r in results)
    if no_version_count:
        warn(f"{no_version_count} service(s) had no version — CVE lookup skipped for those.")
    log(f"CVE lookup complete — {total_cves} CVE(s) across {len(results) - no_version_count} service(s)")
    return results
