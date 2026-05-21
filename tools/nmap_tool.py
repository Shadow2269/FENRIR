"""
tools/nmap_tool.py
Wrapper around nmap that enforces scope validation before every scan.
"""
import subprocess
import shutil
from security.validator import validate_tool
from config import OPSEC_MODE


# Vordefinierte Scan-Profile: key → (label, beschreibung, flags, timeout)
SCAN_TYPES: dict[str, tuple[str, str, list[str], int]] = {
    "1": ("Quick Scan",      "Top 100 Ports, schnell",                              ["-T4", "-F"],                     60),
    "2": ("Service Scan",    "Versionserkennung (Standard)",                        ["-sV"],                          120),
    "3": ("Full Port Scan",  "Alle 65535 Ports + Versionserkennung",               ["-sV", "-p-"],                   600),
    "4": ("OS Detection",    "OS-Fingerprinting + Versionserkennung",              ["-sV", "-O"],                    180),
    "5": ("Vuln Scan",       "NSE Vuln-Scripts (EternalBlue, Shellshock, etc.)",   ["-sV", "--script", "vuln"],      900),
}

# OPSEC flag injections applied on top of any scan-type flags
_OPSEC_FLAGS = ["-T1", "--scan-delay", "2s", "--randomize-hosts", "--max-retries", "1"]


def _apply_opsec(flags: list[str], timeout: int) -> tuple[list[str], int]:
    """Strip aggressive timing flags and inject stealth alternatives."""
    stripped = [f for f in flags if not (f.startswith("-T") and len(f) == 3)]
    return _OPSEC_FLAGS + stripped, max(timeout, 900)


def run_nmap(
    target: str,
    flags: list[str] | None = None,
    confirmed: bool = False,
    timeout: int = 120,
) -> dict:
    """
    Run nmap against *target* after scope validation.

    Args:
        target:    IP address, hostname, or CIDR range.
        flags:     Additional nmap flags (default: ["-sV"]).
        confirmed: Skip target scope check (user confirmed interactively).
        timeout:   Max seconds before killing nmap (default 120).

    Returns:
        dict with keys: success (bool), target, output (str), error (str)
    """
    import sys
    _nmap = "nmap.exe" if sys.platform == "win32" else "nmap"
    if shutil.which(_nmap) is None:
        return {
            "success": False,
            "target": target,
            "output": "",
            "error": "nmap is not installed or not in PATH.",
        }

    ok, reason = validate_tool("nmap", target, authorized=confirmed)
    if not ok:
        return {
            "success": False,
            "target": target,
            "output": "",
            "error": f"Blocked by security policy: {reason}",
        }

    effective_flags = list(flags or ["-sV"])
    if OPSEC_MODE:
        effective_flags, timeout = _apply_opsec(effective_flags, timeout)

    cmd = ["nmap"] + effective_flags + [target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    return {
        "success": result.returncode == 0,
        "target": target,
        "output": result.stdout,
        "error": result.stderr,
    }
