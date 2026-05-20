"""
tools/dns_recon.py
Full DNS reconnaissance: WHOIS lookup, DNS record enumeration (A, AAAA, MX,
NS, TXT, CNAME, SOA), and zone transfer attempt (AXFR).

Dependencies: dnspython (already in requirements.txt), python-whois
"""
import socket
from dataclasses import dataclass, field

import dns.resolver
import dns.zone
import dns.query
import dns.exception


@dataclass
class DNSReconResult:
    success:               bool
    target:                str
    whois_data:            dict  = field(default_factory=dict)
    records:               dict  = field(default_factory=dict)   # type → list[str]
    zone_transfer_possible: bool = False
    zone_transfer_records: list  = field(default_factory=list)
    error:                 str   = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.records or self.whois_data)


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def _run_whois(domain: str) -> dict:
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        data = {}

        def _str(v):
            if v is None:
                return ""
            if isinstance(v, list):
                return ", ".join(str(x) for x in v if x)
            return str(v)

        for key in ("domain_name", "registrar", "creation_date", "expiration_date",
                    "updated_date", "name_servers", "status", "emails",
                    "org", "country"):
            val = getattr(w, key, None)
            s = _str(val)
            if s:
                data[key] = s
        return data
    except Exception as exc:
        return {"error": str(exc)}


# ── DNS records ───────────────────────────────────────────────────────────────

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _query_records(domain: str, resolver: dns.resolver.Resolver) -> dict:
    records: dict[str, list[str]] = {}
    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=8)
            records[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception:
            pass
    return records


# ── Zone transfer ─────────────────────────────────────────────────────────────

def _try_zone_transfer(domain: str, ns_records: list[str]) -> tuple[bool, list[str]]:
    """Attempt AXFR against each nameserver. Returns (success, record_lines)."""
    for ns_raw in ns_records:
        ns = ns_raw.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8, lifetime=10))
            lines = []
            for name, node in sorted(z.nodes.items()):
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        lines.append(f"{name}.{domain} {rdataset.ttl} {rdataset.rdtype.name} {rdata}")
            if lines:
                return True, lines
        except Exception:
            continue
    return False, []


# ── Main entry point ──────────────────────────────────────────────────────────

def run_dns_recon(domain: str) -> DNSReconResult:
    """
    Full DNS reconnaissance for *domain*.

    1. WHOIS lookup
    2. DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA)
    3. Zone transfer attempt (AXFR) against all nameservers
    """
    # Strip any http(s):// prefix
    domain = domain.lower().strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 8
    resolver.lifetime = 10

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    whois_data = _run_whois(domain)

    # ── DNS records ───────────────────────────────────────────────────────────
    try:
        records = _query_records(domain, resolver)
    except Exception as exc:
        return DNSReconResult(success=False, target=domain, error=str(exc))

    # ── Zone transfer ─────────────────────────────────────────────────────────
    zt_possible = False
    zt_records  = []
    ns_list = records.get("NS", [])
    if ns_list:
        zt_possible, zt_records = _try_zone_transfer(domain, ns_list)

    return DNSReconResult(
        success=True,
        target=domain,
        whois_data=whois_data,
        records=records,
        zone_transfer_possible=zt_possible,
        zone_transfer_records=zt_records,
    )
