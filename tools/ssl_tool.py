"""
tools/ssl_tool.py
SSL/TLS certificate and protocol security analysis using Python's ssl stdlib.
"""
import ssl
import socket
import datetime
from dataclasses import dataclass, field
from logger import warn, log


@dataclass
class SslFinding:
    severity: str   # Critical / High / Medium / Low / Info
    title: str
    detail: str


@dataclass
class SslResult:
    target: str
    port: int
    reachable: bool = False
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    days_until_expiry: int = 0
    cert_expired: bool = False
    self_signed: bool = False
    tls10_enabled: bool = False
    tls11_enabled: bool = False
    tls12_enabled: bool = False
    tls13_enabled: bool = False
    negotiated_version: str = ""
    cipher_name: str = ""
    findings: list[SslFinding] = field(default_factory=list)
    error: str = ""

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "Critical" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == "High" for f in self.findings)


def check_ssl(target: str, port: int = 443) -> SslResult:
    """Perform SSL/TLS analysis on target:port."""
    result = SslResult(target=target, port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                result.reachable = True
                result.negotiated_version = ssock.version() or ""
                cipher = ssock.cipher()
                result.cipher_name = cipher[0] if cipher else ""

                cert = ssock.getpeercert()
                if cert:
                    result.cert_subject = _extract_cn(cert.get("subject", ()))
                    result.cert_issuer  = _extract_cn(cert.get("issuer", ()))
                    not_after = cert.get("notAfter", "")
                    result.cert_expiry  = not_after
                    result.days_until_expiry = _days_until(not_after)
                    result.cert_expired = result.days_until_expiry < 0
                    result.self_signed  = result.cert_subject == result.cert_issuer
    except Exception as exc:
        result.error = str(exc)
        return result

    result.tls10_enabled = _test_tls_version(target, port, "TLSv1")
    result.tls11_enabled = _test_tls_version(target, port, "TLSv1_1")
    result.tls12_enabled = _test_tls_version(target, port, "TLSv1_2")
    result.tls13_enabled = _test_tls_version(target, port, "TLSv1_3")

    result.findings = _analyze(result)
    return result


def _test_tls_version(host: str, port: int, version_name: str) -> bool:
    """Return True if the server accepts the given TLS version string (e.g. 'TLSv1_1')."""
    try:
        tls_version = getattr(ssl.TLSVersion, version_name, None)
        if tls_version is None:
            return False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _extract_cn(rdns_tuple) -> str:
    for rdn in rdns_tuple:
        for attr in rdn:
            if attr[0] == "commonName":
                return attr[1]
    return ""


def _days_until(not_after: str) -> int:
    """Parse SSL cert expiry string and return days remaining (negative = expired)."""
    if not not_after:
        return 0
    try:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.datetime.utcnow()).days
    except ValueError:
        return 0


def _analyze(r: SslResult) -> list[SslFinding]:
    findings = []

    if r.cert_expired:
        findings.append(SslFinding("Critical", "Certificate Expired",
            f"Certificate expired {abs(r.days_until_expiry)} day(s) ago. "
            "Browsers show a hard security warning — users cannot connect safely. Renew immediately."))
    elif 0 < r.days_until_expiry <= 14:
        findings.append(SslFinding("Critical", "Certificate Expires in ≤14 Days",
            f"Certificate expires in {r.days_until_expiry} days. Renew now to avoid service disruption."))
    elif 0 < r.days_until_expiry <= 30:
        findings.append(SslFinding("High", "Certificate Expires Soon",
            f"Certificate expires in {r.days_until_expiry} days. Renew immediately."))
    elif 0 < r.days_until_expiry <= 90:
        findings.append(SslFinding("Medium", "Certificate Expires Within 90 Days",
            f"Certificate expires in {r.days_until_expiry} days. Schedule renewal."))

    if r.self_signed:
        findings.append(SslFinding("High", "Self-Signed Certificate",
            "The certificate is not issued by a trusted CA. Clients cannot verify the server's identity. "
            "Replace with a certificate from a trusted CA (e.g. Let's Encrypt — free)."))

    if r.tls10_enabled:
        findings.append(SslFinding("High", "TLS 1.0 Enabled",
            "TLS 1.0 was deprecated in 2021 and is vulnerable to POODLE and BEAST attacks. "
            "Disable TLS 1.0 in your web server config. Support TLS 1.2 and 1.3 only."))

    if r.tls11_enabled:
        findings.append(SslFinding("Medium", "TLS 1.1 Enabled",
            "TLS 1.1 is deprecated (RFC 8996, 2021). "
            "Disable it and configure the server to accept TLS 1.2 and 1.3 only."))

    if not r.tls12_enabled and not r.tls13_enabled:
        findings.append(SslFinding("Critical", "No Modern TLS Version Supported",
            "Neither TLS 1.2 nor TLS 1.3 appears to be supported. "
            "This is a severe misconfiguration — all modern clients will fail to connect securely."))

    cipher = r.cipher_name.upper()
    weak_keywords = ["RC4", "DES", "NULL", "EXPORT", "ANON", "MD5"]
    for kw in weak_keywords:
        if kw in cipher:
            findings.append(SslFinding("High", f"Weak Cipher Suite: {r.cipher_name}",
                f"The negotiated cipher contains weak algorithm '{kw}'. "
                "Configure the server to prefer ECDHE+AES-GCM or ChaCha20-Poly1305 cipher suites."))
            break

    if not findings:
        findings.append(SslFinding("Info", "SSL/TLS Configuration OK",
            "No significant SSL/TLS issues detected with the current configuration."))

    return findings
