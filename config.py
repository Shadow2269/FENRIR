"""
FENRIR — config.py
Central configuration — all settings live here.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Engine-Option ────────────────────────────────────────────────────────────
# "local"      → local Mistral-Modell  (engines/engine_local.py)
# "anthropic"  → Anthropic Cloud API   (engines/engine_anthropic.py)
ENGINE: str = os.getenv("ENGINE", "local")

# ── API Keys ──────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")      
HF_TOKEN: str = os.getenv("HF_TOKEN", "")          #

# ── AI Engine ─────────────────────────────────────────────────────────────────
AI_MODEL: str = "claude-sonnet-4-5"          
MAX_TOKENS: int = 2048
DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

# ── Allowed attack tools ──────────────────────────────────────────────────────
ALLOWED_TOOLS: list[str] = ["nmap", "gobuster"]

# ── Allowed scan targets (IPs, CIDRs, hostnames) ──────────────────────────────
ALLOWED_TARGETS: list[str] = [
    "127.0.0.1",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "scanme.nmap.org",
]

# ── Report output directory ───────────────────────────────────────────────────
REPORT_DIR: str = os.getenv("REPORT_DIR", "result")