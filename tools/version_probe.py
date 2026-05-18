"""
tools/version_probe.py
Detects software versions for services where nmap -sV returned no version string.
Servers often suppress versions via ServerTokens Prod / server_tokens off, but
leak them in error pages, TCP banners, response headers, or via behavior.

Techniques (in order of reliability):
  HTTP(S) 1. Server/X-Powered-By header  (present when server_tokens not fully locked)
          2. 404 error page body  (default error pages embed version)
          3. OPTIONS/HEAD headers  (extra headers sometimes visible on error responses)
          4. [nginx] stub_status paths  (/nginx_status, /status, /server-status …)
          5. [nginx] Info-leak paths  (robots.txt, security.txt, CHANGELOG …)
          6. ALL response headers scan  (any header may expose a version string)
          7. [nginx] Behavioral Range-header fingerprinting  (version estimate)
  FTP     8. 220 TCP banner  (ProFTPD always writes its version there by default)
  TCP     9. Generic banner grab  (SMTP, POP3, IMAP, etc.)
"""
import re
import ssl
import http.client
import socket
import urllib3
import requests
from dataclasses import dataclass, field

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 8  # seconds per probe attempt


@dataclass
class VersionProbeResult:
    port: int
    product: str
    version: str
    method: str   # human-readable explanation of how the version was found
    is_estimate: bool = field(default=False)   # True when version is behavioral estimate


# ── Pattern tables ────────────────────────────────────────────────────────────

# (regex, product_name) — matched against headers and response bodies
_VERSION_PATTERNS: list[tuple[str, str]] = [
    # Web servers
    (r"Apache/(\d[\d.]+)",                          "Apache httpd"),
    (r"nginx/(\d[\d.]+)",                           "nginx"),
    (r"lighttpd/(\d[\d.]+)",                        "lighttpd"),
    (r"Microsoft-IIS/(\d[\d.]+)",                   "Microsoft IIS httpd"),
    (r"LiteSpeed/(\d[\d.]+)",                       "LiteSpeed"),
    (r"Caddy/(\d[\d.]+)",                           "Caddy"),
    (r"Jetty\((\d[\d.]+)\)",                        "Jetty"),
    (r"Tomcat/(\d[\d.]+)",                          "Apache Tomcat"),
    # Runtime / scripting
    (r"PHP/(\d[\d.]+)",                             "PHP"),
    (r"Python/(\d[\d.]+)",                          "Python"),
    (r"Ruby/(\d[\d.]+)",                            "Ruby"),
    (r"Node\.js/(\d[\d.]+)",                        "Node.js"),
    # FTP
    (r"ProFTPD (\d[\d.]+)",                         "ProFTPD"),
    (r"vsFTPd (\d[\d.]+)",                          "vsftpd"),
    (r"FileZilla Server (?:version )?(\d[\d.]+)",   "FileZilla"),
    # Mail
    (r"Exim (\d[\d.]+)",                            "Exim"),
    (r"Sendmail (\d[\d.]+)",                        "Sendmail"),
    (r"Postfix/(\d[\d.]+)",                         "Postfix"),
    (r"Dovecot/(\d[\d.]+)",                         "Dovecot"),
    # Other
    (r"OpenSSH[_-](\d[\d.p]+)",                     "OpenSSH"),
    (r"OpenSSL/(\d[\d.]+\w*)",                      "OpenSSL"),
]

# Standard headers that often expose a version string
_VERSION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Runtime",
    "X-Version",
]

# nginx-specific: stub_status and monitoring endpoints
_NGINX_STATUS_PATHS = [
    "/nginx_status",
    "/_nginx_status",
    "/nginx-status",
    "/status",
    "/_status",
    "/server-status",
    "/nstatus",
]

# Paths that sometimes leak version strings in their body
_INFO_LEAK_PATHS = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/readme.html",
    "/README",
    "/CHANGELOG",
    "/version",
    "/version.txt",
    "/app/version",
    "/api/version",
]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _match_version(text: str, source: str) -> VersionProbeResult | None:
    """Return first VersionProbeResult found in *text*, or None."""
    for pattern, product in _VERSION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return VersionProbeResult(
                port=0,
                product=product,
                version=m.group(1),
                method=source,
            )
    return None


def _scan_all_headers(headers, source_label: str) -> VersionProbeResult | None:
    """Scan every response header for a version string (not just the standard list)."""
    for key, val in headers.items():
        result = _match_version(val, f"header '{key}' ({source_label})")
        if result:
            return result
    return None


def _http_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "FENRIR-VersionProbe/1.0"
    return s


# ── HTTP(S) version probe — standard techniques ───────────────────────────────

def probe_http_version(host: str, port: int, is_https: bool) -> VersionProbeResult | None:
    """
    Probe an HTTP/HTTPS port using standard techniques:
      1. HEAD / → Server header + version headers
      2. GET /fenrir_probe_404 → 404 error page body
      3. OPTIONS / → Server header
    Returns a VersionProbeResult or None.
    """
    scheme = "https" if is_https else "http"
    base = f"{scheme}://{host}:{port}"
    session = _http_session()

    # ── Technique 1: HEAD / ───────────────────────────────────────────────────
    try:
        resp = session.head(base + "/", timeout=_TIMEOUT, allow_redirects=True)
        for header in _VERSION_HEADERS:
            val = resp.headers.get(header, "")
            if val:
                result = _match_version(val, f"{header} header")
                if result:
                    result.port = port
                    return result
    except Exception:
        pass

    # ── Technique 2: GET non-existent path → 404 error page ──────────────────
    try:
        resp = session.get(
            base + "/fenrir_probe_not_found_xyz_abc",
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
        for header in _VERSION_HEADERS:
            val = resp.headers.get(header, "")
            if val:
                result = _match_version(val, f"{header} header (404)")
                if result:
                    result.port = port
                    return result
        body = resp.text[:4000]
        result = _match_version(body, "404 error page body")
        if result:
            result.port = port
            return result
    except Exception:
        pass

    # ── Technique 3: OPTIONS / ───────────────────────────────────────────────
    try:
        resp = session.options(base + "/", timeout=_TIMEOUT, allow_redirects=False)
        for header in _VERSION_HEADERS:
            val = resp.headers.get(header, "")
            if val:
                result = _match_version(val, f"{header} header (OPTIONS)")
                if result:
                    result.port = port
                    return result
    except Exception:
        pass

    return None


# ── nginx extended probing ────────────────────────────────────────────────────

def probe_nginx_extended(host: str, port: int, is_https: bool) -> VersionProbeResult | None:
    """
    Extended nginx-specific version detection used when standard probing fails.

    Techniques in order:
      A. HTTP/2 ALPN negotiation (HTTPS only) → confirms nginx ≥ 1.9.5 if h2 accepted
      B. stub_status / monitoring endpoints → may expose version in headers or body
      C. Info-leak paths (robots.txt, CHANGELOG …) → sometimes contain version
      D. ALL response headers on GET / → catch non-standard version headers
      E. Behavioral Range-header fingerprinting + conservative fallback
    """
    scheme = "https" if is_https else "http"
    base = f"{scheme}://{host}:{port}"
    session = _http_session()

    # ── A: HTTP/2 ALPN negotiation (HTTPS only) ───────────────────────────────
    if is_https:
        h2 = _nginx_h2_check(host, port)
        if h2:
            version, reason = h2
            return VersionProbeResult(
                port=port, product="nginx", version=version,
                method=f"ALPN negotiation ({reason}) — version estimate",
                is_estimate=True,
            )

    # ── B: stub_status + monitoring paths ────────────────────────────────────
    for path in _NGINX_STATUS_PATHS:
        try:
            resp = session.get(base + path, timeout=_TIMEOUT, allow_redirects=False)
            if resp.status_code not in (200, 206):
                continue
            # Scan all headers first
            result = _scan_all_headers(resp.headers, f"stub_status {path}")
            if result:
                result.port = port
                return result
            # Scan body (some status pages embed version in output)
            result = _match_version(resp.text[:3000], f"stub_status body {path}")
            if result:
                result.port = port
                return result
        except Exception:
            pass

    # ── C: Info-leak paths ────────────────────────────────────────────────────
    for path in _INFO_LEAK_PATHS:
        try:
            resp = session.get(base + path, timeout=_TIMEOUT, allow_redirects=False)
            if resp.status_code != 200:
                continue
            result = _scan_all_headers(resp.headers, f"info path {path}")
            if result:
                result.port = port
                return result
            result = _match_version(resp.text[:3000], f"info path body {path}")
            if result:
                result.port = port
                return result
        except Exception:
            pass

    # ── D: Scan ALL response headers on main page ─────────────────────────────
    try:
        resp = session.get(base + "/", timeout=_TIMEOUT, allow_redirects=True)
        result = _scan_all_headers(resp.headers, "GET / all headers")
        if result:
            result.port = port
            return result
    except Exception:
        pass

    # ── E: Behavioral fingerprinting + conservative fallback ─────────────────
    estimate = _nginx_behavioral_estimate(host, port, is_https)
    if estimate:
        version, reason = estimate
        return VersionProbeResult(
            port=port, product="nginx", version=version,
            method=f"behavioral fingerprint ({reason}) — version estimate, not exact",
            is_estimate=True,
        )

    return None


def _nginx_h2_check(host: str, port: int) -> tuple[str, str] | None:
    """
    Check HTTP/2 support via ALPN TLS negotiation.
    nginx >= 1.9.5 supports h2 (HTTP/2).
    Returns (version_estimate, reason) or None on connection failure.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                proto = ssock.selected_alpn_protocol()
                if proto == "h2":
                    return ("1.9", "h2 ALPN accepted → nginx ≥ 1.9.5")
                return ("1.0", "h2 ALPN not offered → nginx without HTTP/2")
    except Exception:
        pass
    return None


def _nginx_behavioral_estimate(host: str, port: int, is_https: bool) -> tuple[str, str] | None:
    """
    Use HTTP Range-header behavior + conservative fallback to estimate nginx version.

    Behavioral markers (in priority order):
      1. Alt-Svc h3 header → nginx ≥ 1.21.0
      2. 206 multipart response to multi-range GET → nginx ≥ 1.9.2
      3. Server responded at all (any status) → conservative "1.0" minimum estimate
         so CVE lookup still runs (results will be marked unverified)

    Returns (version_string, reason) or None only if server is completely unreachable.
    """
    try:
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=_TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=_TIMEOUT)

        conn.request(
            "GET", "/",
            headers={
                "Range": "bytes=0-0,1-1",
                "Host": host,
                "User-Agent": "FENRIR-VersionProbe/1.0",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        status = resp.status
        ct   = resp.getheader("Content-Type", "")
        alt  = resp.getheader("Alt-Svc", "")
        conn.close()

        # Precise behavioral markers
        if "h3" in alt or "quic" in alt.lower():
            return ("1.21", f"Alt-Svc h3 hint → nginx ≥ 1.21.0")
        if status == 206 and "multipart/byteranges" in ct:
            return ("1.9", "206 multipart/byteranges → nginx ≥ 1.9.2")

        # Server responded (2xx / 3xx / 4xx / 5xx) — version undeterminable via Range
        # because the backend error (502 etc.) masks the Range behavior.
        # Return minimum estimate so CVE lookup can still produce unverified results.
        return ("1.0", f"server reachable HTTP {status} — exact version unknown, minimum estimate")

    except Exception:
        pass

    return None


# ── TCP banner probe ──────────────────────────────────────────────────────────

def probe_tcp_banner(host: str, port: int, send: bytes = b"") -> VersionProbeResult | None:
    """
    Connect to a TCP port, optionally send a greeting, and read the banner.
    Works for FTP, SMTP, POP3, IMAP, etc.
    """
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        banner = sock.recv(2048).decode("utf-8", errors="ignore")
        if send:
            sock.sendall(send)
            banner += sock.recv(2048).decode("utf-8", errors="ignore")
        sock.close()

        result = _match_version(banner, f"TCP banner (port {port})")
        if result:
            result.port = port
            return result
    except Exception:
        pass
    return None


# ── Main enrichment entry point ───────────────────────────────────────────────

def enrich_services(host: str, services: list[dict]) -> list[dict]:
    """
    For each service in *services* that has no version string, attempt to probe
    the version using the techniques above.  Updates the 'version' field
    in-place and adds 'version_probe_method' and optionally 'version_is_estimate'.

    Returns the (modified) services list.
    """
    for svc in services:
        if svc.get("version"):
            continue  # already has a version — nothing to do

        port    = svc["port"]
        service = svc["service"].lower()
        product = svc.get("product", "").lower()
        result  = None

        # HTTP / HTTPS — standard probe first
        if (
            "http" in service or
            port in (80, 8080, 8000, 3000, 5000, 8888, 8443, 443, 4443)
        ):
            is_https = (
                service.startswith("ssl/") or
                "https" in service or
                port in (443, 8443, 4443)
            )
            result = probe_http_version(host, port, is_https)

            # nginx-specific extended probing when standard techniques fail
            if not result and "nginx" in product:
                result = probe_nginx_extended(host, port, is_https)

        # FTP
        elif "ftp" in service or port == 21:
            result = probe_tcp_banner(host, port)

        # SMTP
        elif "smtp" in service or port in (25, 465, 587):
            result = probe_tcp_banner(host, port, send=b"EHLO fenrir-probe\r\n")

        # POP3
        elif "pop3" in service or port in (110, 995):
            result = probe_tcp_banner(host, port)

        # IMAP
        elif "imap" in service or port in (143, 993):
            result = probe_tcp_banner(host, port, send=b"A001 CAPABILITY\r\n")

        # Generic TCP banner for anything else
        else:
            result = probe_tcp_banner(host, port)

        if result and result.version:
            # Sanity check: probed product must loosely match what nmap reported
            nmap_product    = svc.get("product", "").lower()
            probed_product  = result.product.lower()
            if (
                not nmap_product
                or any(kw in probed_product for kw in nmap_product.split())
                or any(kw in nmap_product for kw in probed_product.split())
            ):
                svc["version"]              = result.version
                svc["version_probe_method"] = result.method
                svc["version_is_estimate"]  = result.is_estimate
                if not svc.get("product") and result.product:
                    svc["product"] = result.product

    return services
