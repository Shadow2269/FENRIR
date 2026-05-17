"""
tools/subdomain_tool.py
Subdomain enumeration via subfinder/amass (external tools) with crt.sh API fallback.

Priority: subfinder -> amass -> crt.sh
"""
import shutil
import subprocess
import requests
from dataclasses import dataclass, field
from security.validator import validate_tool
from logger import warn


@dataclass
class SubdomainResult:
    success: bool
    target: str
    subdomains: list[str] = field(default_factory=list)
    source: str = ""   # "subfinder" | "amass" | "crt.sh"
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.subdomains)

    @property
    def interesting(self) -> list[str]:
        """Subdomains that commonly indicate sensitive services."""
        keywords = {
            "admin", "api", "dev", "staging", "test", "internal",
            "vpn", "mail", "smtp", "ftp", "ssh", "jenkins", "gitlab",
            "jira", "confluence", "dashboard", "portal", "manage",
            "login", "auth", "beta", "old", "backup", "legacy", "uat",
        }
        result = []
        for sub in self.subdomains:
            parts = sub.split(".")
            if parts and any(kw in parts[0].lower() for kw in keywords):
                result.append(sub)
        return result


def run_subdomain_enum(
    domain: str,
    confirmed: bool = False,
    timeout: int = 120,
) -> SubdomainResult:
    """
    Enumerate subdomains for *domain*.
    Tries subfinder -> amass -> crt.sh in order.
    Returns deduplicated, sorted SubdomainResult.
    """
    ok, reason = validate_tool("subdomain", domain, authorized=confirmed)
    if not ok:
        return SubdomainResult(success=False, target=domain, error=f"Blocked: {reason}")

    result = _try_subfinder(domain, timeout)
    if result is not None:
        return result

    result = _try_amass(domain, timeout)
    if result is not None:
        return result

    warn("subfinder/amass not found — falling back to crt.sh passive lookup")
    return _try_crtsh(domain)


def _try_subfinder(domain: str, timeout: int) -> SubdomainResult | None:
    bin_path = shutil.which("subfinder") or shutil.which("subfinder.exe")
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [bin_path, "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subdomains = _clean(proc.stdout.splitlines())
        return SubdomainResult(
            success=True,
            target=domain,
            subdomains=subdomains,
            source="subfinder",
        )
    except subprocess.TimeoutExpired:
        warn(f"subfinder timed out after {timeout}s")
        return None
    except Exception as exc:
        warn(f"subfinder error: {exc}")
        return None


def _try_amass(domain: str, timeout: int) -> SubdomainResult | None:
    bin_path = shutil.which("amass") or shutil.which("amass.exe")
    if not bin_path:
        return None
    try:
        proc = subprocess.run(
            [bin_path, "enum", "-passive", "-d", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        subdomains = _clean(proc.stdout.splitlines())
        return SubdomainResult(
            success=True,
            target=domain,
            subdomains=subdomains,
            source="amass",
        )
    except subprocess.TimeoutExpired:
        warn(f"amass timed out after {timeout}s")
        return None
    except Exception as exc:
        warn(f"amass error: {exc}")
        return None


def _try_crtsh(domain: str) -> SubdomainResult:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(
            url,
            timeout=30,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()

        raw: list[str] = []
        for entry in data:
            for line in entry.get("name_value", "").splitlines():
                raw.append(line.strip().lstrip("*."))

        subdomains = _clean([s for s in raw if s.endswith(f".{domain}") or s == domain])
        return SubdomainResult(
            success=True,
            target=domain,
            subdomains=subdomains,
            source="crt.sh",
        )
    except Exception as exc:
        return SubdomainResult(
            success=False,
            target=domain,
            error=f"crt.sh lookup failed: {exc}",
            source="crt.sh",
        )


def _clean(lines: list[str]) -> list[str]:
    """Deduplicate, strip whitespace, lowercase, sort."""
    return sorted({line.strip().lower() for line in lines if line.strip()})
