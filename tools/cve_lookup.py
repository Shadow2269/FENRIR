"""
tools/cve_lookup.py
Queries the NVD (National Vulnerability Database) API for CVEs
based on software names and versions found in an nmap scan.
"""

import re
import time
import requests
from dataclasses import dataclass, field
from logger import log, warn


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 6.5   # seconds between requests (safe under the 5/30s limit)


@dataclass
class CVEEntry:
    cve_id: str           # e.g. CVE-2021-41773
    description: str      # short English description
    cvss_score: float     # 0.0 – 10.0
    cvss_severity: str    # None / Low / Medium / High / Critical
    cvss_vector: str      # CVSS vector string
    published: str        # publication date
    url: str              # link to NVD page


@dataclass
class ServiceCVEResult:
    port: int
    protocol: str         # tcp / udp
    service: str          # e.g. http
    product: str          # e.g. Apache httpd
    version: str          # e.g. 2.4.49
    cves: list[CVEEntry] = field(default_factory=list)

    @property
    def max_cvss(self) -> float:
        return max((c.cvss_score for c in self.cves), default=0.0)

    @property
    def critical_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.cvss_severity == "Critical"]

    @property
    def high_cves(self) -> list[CVEEntry]:
        return [c for c in self.cves if c.cvss_severity == "High"]


# ── nmap output parser ────────────────────────────────────────────────────────

def parse_nmap_services(nmap_output: str) -> list[dict]:
    """
    Extract service/version info from nmap -sV output.

    Returns a list of dicts:
      { port, protocol, state, service, product, version }

    Example nmap line:
      80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
      22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
    """
    services = []

    # Matches: PORT/PROTO STATE SERVICE PRODUCT VERSION (extra)
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s+(.*?)$",
        re.MULTILINE,
    )

    for match in pattern.finditer(nmap_output):
        port, proto, state, service, rest = match.groups()

        # Split product from version — version usually starts with a digit
        # e.g. "Apache httpd 2.4.49 ((Unix))" → product="Apache httpd", version="2.4.49"
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
    """Split 'Apache httpd 2.4.49 ((Unix))' into ('Apache httpd', '2.4.49')."""
    text = re.sub(r"\(.*?\)", "", text).strip()   # remove parenthetical extras
    # Find the first version-looking token (starts with digit)
    version_match = re.search(r"\b(\d[\d.]+\w*)\b", text)
    if version_match:
        version = version_match.group(1)
        product = text[:version_match.start()].strip()
        return product, version
    return text, ""


# ── NVD API client ────────────────────────────────────────────────────────────

def lookup_cves(
    keyword: str,
    max_results: int = 5,
    api_key: str = "",
) -> list[CVEEntry]:
    """
    Search NVD for CVEs matching *keyword* (e.g. "Apache httpd 2.4.49").
    Returns up to *max_results* entries sorted by CVSS score descending.

    Args:
        keyword:     Product name + version string to search.
        max_results: How many CVEs to return (default 5 per service).
        api_key:     Optional NVD API key for higher rate limits.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max(max_results, 20),   # fetch more, filter after
        "startIndex": 0,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        warn(f"NVD API error for '{keyword}': {exc}")
        return []

    entries = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (prefer English)
        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            "No description available.",
        )

        # CVSS score — prefer v3.1, fall back to v3.0, then v2
        score, severity, vector = _extract_cvss(cve)

        published = cve.get("published", "")[:10]   # just the date part
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        entries.append(CVEEntry(
            cve_id=cve_id,
            description=description[:300],           # keep it short
            cvss_score=score,
            cvss_severity=severity,
            cvss_vector=vector,
            published=published,
            url=url,
        ))

    # Sort by CVSS score descending, return top N
    entries.sort(key=lambda e: e.cvss_score, reverse=True)
    return entries[:max_results]


def _extract_cvss(cve: dict) -> tuple[float, str, str]:
    """Extract the best available CVSS score from a CVE entry."""
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


# ── Main entry point ──────────────────────────────────────────────────────────

def run_cve_lookup(
    nmap_output: str,
    max_cves_per_service: int = 5,
    api_key: str = "",
) -> list[ServiceCVEResult]:
    """
    Parse nmap output, look up CVEs for each discovered service,
    and return a list of ServiceCVEResult objects.

    Args:
        nmap_output:          Raw stdout from an nmap -sV scan.
        max_cves_per_service: How many CVEs to return per service (default 5).
        api_key:              Optional NVD API key.
    """
    services = parse_nmap_services(nmap_output)

    if not services:
        warn("No versioned services found in nmap output — nothing to look up.")
        return []

    log(f"CVE lookup: found {len(services)} service(s) — querying NVD API …")
    results = []

    for svc in services:
        # Build search keyword: "product version" e.g. "Apache httpd 2.4.49"
        keyword = f"{svc['product']} {svc['version']}".strip()
        if not keyword:
            continue

        log(f"  Querying NVD: '{keyword}' …")
        cves = lookup_cves(keyword, max_cves_per_service, api_key)

        results.append(ServiceCVEResult(
            port=svc["port"],
            protocol=svc["protocol"],
            service=svc["service"],
            product=svc["product"],
            version=svc["version"],
            cves=cves,
        ))

        # Respect NVD rate limit between requests
        time.sleep(REQUEST_DELAY)

    total_cves = sum(len(r.cves) for r in results)
    log(f"CVE lookup complete — {total_cves} CVE(s) found across {len(results)} service(s)")
    return results
