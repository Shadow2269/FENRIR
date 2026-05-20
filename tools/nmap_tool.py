"""
tools/nmap_tool.py
Wrapper around nmap that enforces scope validation before every scan.
"""
import subprocess
import shutil
from security.validator import validate_tool


# Vordefinierte Scan-Profile: key → (label, beschreibung, flags, timeout)
SCAN_TYPES: dict[str, tuple[str, str, list[str], int]] = {
    "1": ("Quick Scan",      "Top 100 Ports, schnell",                              ["-T4", "-F"],                     60),
    "2": ("Service Scan",    "Versionserkennung (Standard)",                        ["-sV"],                          120),
    "3": ("Full Port Scan",  "Alle 65535 Ports + Versionserkennung",               ["-sV", "-p-"],                   600),
    "4": ("OS Detection",    "OS-Fingerprinting + Versionserkennung",              ["-sV", "-O"],                    180),
    "5": ("Vuln Scan",       "NSE Vuln-Scripts (EternalBlue, Shellshock, etc.)",   ["-sV", "--script", "vuln"],      900),
}


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

    cmd = ["nmap"] + (flags or ["-sV"]) + [target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    return {
        "success": result.returncode == 0,
        "target": target,
        "output": result.stdout,
        "error": result.stderr,
    }
