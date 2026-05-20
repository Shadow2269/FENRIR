"""
tools/subdomain_tool.py
Subdomain enumeration via subfinder/amass (external tools) with crt.sh API fallback.

Priority: subfinder -> amass -> crt.sh
"""
import os
import sys
import shutil
import subprocess
import requests
from pathlib import Path
from dataclasses import dataclass, field
from security.validator import validate_tool
from logger import warn

_IS_WINDOWS = sys.platform == "win32"


def _fallback_paths(name: str) -> list[str]:
    """Return platform-specific fallback paths for an external binary."""
    go_bin = Path.home() / "go" / "bin"
    if _IS_WINDOWS:
        return [
            str(go_bin / f"{name}.exe"),
            str(go_bin / name),
            rf"C:\Tools\{name}.exe",
            rf"C:\Tools\{name}",
        ]
    # Linux / macOS
    return [
        str(go_bin / name),
        f"/opt/homebrew/bin/{name}",   # Homebrew on Apple Silicon
        f"/usr/local/bin/{name}",      # Homebrew on Intel / Linux manual installs
        f"/usr/bin/{name}",
    ]


_SUBFINDER_PATHS = _fallback_paths("subfinder")
_AMASS_PATHS     = _fallback_paths("amass")


def _find_binary(name: str, extra_paths: list[str]) -> str | None:
    found = shutil.which(name)
    if _IS_WINDOWS:
        found = found or shutil.which(name + ".exe")
    if found:
        return found
    for p in extra_paths:
        if os.path.isfile(p):
            return p
    return None


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

    warn("subfinder/amass not found — falling back to passive API lookup")
    result = _try_crtsh(domain)
    if not result.success:
        warn("crt.sh failed — trying HackerTarget fallback")
        result = _try_hackertarget(domain)
    return result


def _try_subfinder(domain: str, timeout: int) -> SubdomainResult | None:
    bin_path = _find_binary("subfinder", _SUBFINDER_PATHS)
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
    bin_path = _find_binary("amass", _AMASS_PATHS)
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
    for attempt in range(2):
        try:
            resp = requests.get(
                url,
                timeout=15,
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
            if attempt == 0:
                warn(f"crt.sh attempt 1 failed ({exc}) — retrying …")
            else:
                return SubdomainResult(
                    success=False,
                    target=domain,
                    error=f"crt.sh failed after 2 attempts: {exc}",
                    source="crt.sh",
                )
    return SubdomainResult(success=False, target=domain, error="crt.sh unreachable", source="crt.sh")


def _try_hackertarget(domain: str) -> SubdomainResult:
    """HackerTarget free API — no key needed, returns plain-text subdomain list."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        # Format: subdomain,ip
        subdomains = []
        for line in lines:
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(domain):
                    subdomains.append(sub)
        subdomains = _clean(subdomains)
        if "error" in resp.text.lower() and not subdomains:
            return SubdomainResult(
                success=False,
                target=domain,
                error=f"HackerTarget: {resp.text[:80]}",
                source="hackertarget",
            )
        return SubdomainResult(
            success=True,
            target=domain,
            subdomains=subdomains,
            source="hackertarget",
        )
    except Exception as exc:
        return SubdomainResult(
            success=False,
            target=domain,
            error=f"HackerTarget failed: {exc}",
            source="hackertarget",
        )


def _clean(lines: list[str]) -> list[str]:
    """Deduplicate, strip whitespace, lowercase, sort."""
    return sorted({line.strip().lower() for line in lines if line.strip()})
