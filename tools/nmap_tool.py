"""
tools/nmap_tool.py
Wrapper around nmap that enforces scope validation before every scan.
"""
import subprocess
import shutil
from security.validator import validate_tool


def run_nmap(target: str, flags: list[str] | None = None, confirmed: bool = False) -> dict:
    """
    Run nmap against *target* after scope validation.

    Args:
        target: IP address, hostname, or CIDR range.
        flags:  Additional nmap flags (default: ["-sV"]).

    Returns:
        dict with keys: success (bool), target, output (str), error (str)
    """
    if shutil.which("nmap") is None:
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    return {
        "success": result.returncode == 0,
        "target": target,
        "output": result.stdout,
        "error": result.stderr,
    }
