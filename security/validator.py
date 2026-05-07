"""
security/validator.py
Single authoritative place for target + tool validation.
"""
import ipaddress
from config import ALLOWED_TARGETS, ALLOWED_TOOLS


def is_allowed_target(target: str) -> bool:
    """Return True if *target* is inside ALLOWED_TARGETS (IP, CIDR, or hostname)."""
    try:
        ip = ipaddress.ip_address(target)
        for entry in ALLOWED_TARGETS:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if str(ip) == entry:
                    return True
        return False
    except ValueError:
        # Not an IP — check as hostname
        return target in ALLOWED_TARGETS


def validate_tool(tool: str, target: str, authorized: bool = False) -> tuple[bool, str]:
    """
    Validate that *tool* is permitted and *target* is in scope.

    Args:
        authorized: If True, skip the target scope check (user confirmed interactively).

    Returns:
        (True, "OK")             — allowed
        (False, reason: str)     — blocked with human-readable reason
    """
    if tool not in ALLOWED_TOOLS:
        return False, f"Tool '{tool}' is not in the allowed-tools list: {ALLOWED_TOOLS}"

    if not authorized and not is_allowed_target(target):
        return False, (
            f"Target '{target}' is outside the allowed scope. "
            f"Allowed: {ALLOWED_TARGETS}"
        )

    return True, "OK"
