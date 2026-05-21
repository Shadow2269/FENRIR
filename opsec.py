"""
opsec.py — FENRIR OPSEC helper
Central module for stealth settings. Every tool imports from here instead of
hardcoding User-Agents or delays, so OPSEC_MODE=true flips everything at once.
"""
import time
from config import OPSEC_MODE, OPSEC_DELAY, OPSEC_USER_AGENT

_NORMAL_UA = "Mozilla/5.0 (FENRIR security scanner)"


def get_headers(extra: dict | None = None) -> dict:
    """Return a headers dict with the appropriate User-Agent."""
    h: dict = {"User-Agent": OPSEC_USER_AGENT if OPSEC_MODE else _NORMAL_UA}
    if extra:
        h.update(extra)
    return h


def opsec_sleep() -> None:
    """Sleep OPSEC_DELAY seconds when OPSEC_MODE is active."""
    if OPSEC_MODE and OPSEC_DELAY > 0:
        time.sleep(OPSEC_DELAY)
