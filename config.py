"""
FENRIR — config.py
Central configuration — all settings live here.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ──────────────────────────────────────────────────────────────────
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

# ── Allowed attack tools ──────────────────────────────────────────────────────
ALLOWED_TOOLS: list[str] = ["nmap", "gobuster", "subdomain"]

# ── Allowed scan targets (IPs, CIDRs, hostnames) ──────────────────────────────
ALLOWED_TARGETS: list[str] = [
    "127.0.0.1",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "scanme.nmap.org",
]

# ── Report output directory ───────────────────────────────────────────────────
REPORT_DIR: str = os.getenv("REPORT_DIR", "result")

# ── OPSEC Mode ────────────────────────────────────────────────────────────────
# When true: slow nmap timing, 1-thread gobuster + delay, spoofed UA, inter-
# request sleep on all HTTP tools. Use for internal scans to avoid detection.
OPSEC_MODE:       bool  = os.getenv("OPSEC_MODE", "false").lower() == "true"
OPSEC_DELAY:      float = float(os.getenv("OPSEC_DELAY", "2.0"))   # seconds between HTTP requests
OPSEC_USER_AGENT: str   = os.getenv(
    "OPSEC_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
)