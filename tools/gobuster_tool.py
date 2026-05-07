"""
tools/gobuster_tool.py
Wrapper around gobuster that enforces scope validation before every scan.

Gobuster finds hidden directories and files on web servers by brute-forcing
paths from a wordlist (e.g. /admin, /login, /api/v1).
"""

import subprocess
import shutil
import re
from dataclasses import dataclass, field
from security.validator import validate_tool
from logger import warn


@dataclass
class GobusterFinding:
    path: str           # e.g. /admin
    status: int         # HTTP status code
    size: int           # response size in bytes
    redirect: str       # redirect location if 301/302, else ""


@dataclass
class GobusterResult:
    success: bool
    target: str
    findings: list[GobusterFinding] = field(default_factory=list)
    output: str = ""
    error: str = ""
    wildcard_excluded: str = ""  # response size excluded via --exclude-length on auto-retry

    @property
    def found_paths(self) -> list[GobusterFinding]:
        """Only paths that returned 200/204 (actually accessible)."""
        return [f for f in self.findings if f.status in (200, 204)]

    @property
    def redirect_paths(self) -> list[GobusterFinding]:
        """Paths that redirect — often login pages."""
        return [f for f in self.findings if f.status in (301, 302)]

    @property
    def interesting_paths(self) -> list[GobusterFinding]:
        """200 + 301/302 combined — everything worth investigating."""
        return [f for f in self.findings if f.status in (200, 204, 301, 302)]


def _extract_hostname(url: str) -> str:
    """
    Pull just the hostname out of a URL for scope validation.
    'http://192.168.1.1:8080/path' → '192.168.1.1'
    """
    url = url.replace("https://", "").replace("http://", "")
    host = url.split("/")[0].split(":")[0]
    return host


def _parse_gobuster_output(output: str) -> list[GobusterFinding]:
    """
    Parse gobuster dir output lines like:
      /admin                (Status: 200) [Size: 1234]
      /login                (Status: 301) [Size: 0] [--> /login/]
    """
    findings = []
    pattern = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]"
        r"(?:\s+\[-->\s*(.*?)\])?",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        path, status, size, redirect = match.groups()
        findings.append(GobusterFinding(
            path=path,
            status=int(status),
            size=int(size),
            redirect=redirect or "",
        ))
    return findings


def run_gobuster(
    target_url: str,
    wordlist: str = "wordlists/common.txt",
    extensions: list[str] | None = None,
    threads: int = 10,
    timeout: int = 600,
    extra_flags: list[str] | None = None,
    confirmed: bool = False,
) -> GobusterResult:
    """
    Run gobuster dir against *target_url* after scope validation.

    Args:
        target_url:  Full URL including scheme, e.g. "http://192.168.1.1"
        wordlist:    Path to wordlist file (default: wordlists/common.txt)
        extensions:  File extensions to append, e.g. ["php", "html", "txt"]
        threads:     Parallel threads (default 10 — be careful with low-power targets)
        timeout:     Max seconds before killing gobuster (default 180)
        extra_flags: Any additional gobuster flags, e.g. ["--no-tls-validation"]

    Returns:
        GobusterResult with findings list and raw output.
    """
    # ── Scope check ───────────────────────────────────────────────────────────
    hostname = _extract_hostname(target_url)
    ok, reason = validate_tool("gobuster", hostname, authorized=confirmed)
    if not ok:
        return GobusterResult(
            success=False,
            target=target_url,
            error=f"Blocked by security policy: {reason}",
        )

    # ── Binary check ──────────────────────────────────────────────────────────
    gobuster_bin = shutil.which("gobuster") or shutil.which("gobuster.exe")
    if not gobuster_bin:
        return GobusterResult(
            success=False,
            target=target_url,
            error=(
                "gobuster not found in PATH.\n"
                "Install: choco install gobuster\n"
                "Or download from: https://github.com/OJ/gobuster/releases"
            ),
        )

    # ── Wordlist check ────────────────────────────────────────────────────────
    import os
    if not os.path.isfile(wordlist):
        return GobusterResult(
            success=False,
            target=target_url,
            error=(
                f"Wordlist not found: '{wordlist}'\n"
                "Download SecLists: https://github.com/danielmiessler/SecLists\n"
                "Then set wordlist='SecLists/Discovery/Web-Content/common.txt'"
            ),
        )

    # ── Build command ─────────────────────────────────────────────────────────
    cmd = [
        gobuster_bin, "dir",
        "-u", target_url,
        "-w", wordlist,
        "-t", str(threads),
        "--no-progress",    # cleaner output for parsing
        "--no-error",       # suppress connection errors per path
    ]

    if extensions:
        cmd += ["-x", ",".join(extensions)]

    if extra_flags:
        cmd += extra_flags

    # ── Run ───────────────────────────────────────────────────────────────────
    def _run(command):
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    proc = _run(cmd)
    if proc is None:
        return GobusterResult(
            success=False,
            target=target_url,
            error=f"gobuster timed out or failed after {timeout}s.",
        )

    # ── Wildcard auto-retry ───────────────────────────────────────────────────
    wildcard_pattern = re.compile(r"Length:\s*(\d+)", re.IGNORECASE)
    stderr_combined  = (proc.stderr or "") + (proc.stdout or "")
    wildcard_match   = (
        "non existing urls" in stderr_combined.lower()
        and wildcard_pattern.search(stderr_combined)
    )
    wc_excluded = ""
    if wildcard_match:
        wc_excluded = wildcard_pattern.search(stderr_combined).group(1)
        warn(f"Wildcard detected (all 404s → 200, size {wc_excluded}B) — retrying with --exclude-length {wc_excluded}")
        retry_cmd = cmd + ["--exclude-length", wc_excluded]
        proc = _run(retry_cmd)
        if proc is None:
            return GobusterResult(
                success=False,
                target=target_url,
                error=f"gobuster timed out during wildcard-retry after {timeout}s.",
            )

    output   = proc.stdout
    findings = _parse_gobuster_output(output)

    return GobusterResult(
        success=proc.returncode == 0,
        target=target_url,
        findings=findings,
        output=output,
        error=proc.stderr,
        wildcard_excluded=wc_excluded,
    )
