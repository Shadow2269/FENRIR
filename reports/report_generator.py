"""
reports/report_generator.py
Converts scan results and red-team findings into readable Markdown reports.
"""
import os
import re
import datetime
from config import REPORT_DIR


def _ensure_dir():
    os.makedirs(REPORT_DIR, exist_ok=True)


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# ── Nmap Report ───────────────────────────────────────────────────────────────

def generate_nmap_report(nmap_result: dict, run_cve: bool = True) -> str:
    """
    Generate a Markdown report from a run_nmap() result dict.
    CVE results are read from nmap_result["_cve_results"] if present.
    run_cve is accepted for API compatibility but ignored here
    (the lookup is done in main.py before this call).
    Returns the file path of the saved .md report.
    """
    _ensure_dir()
    ts       = _timestamp()
    target   = nmap_result.get("target", "unknown")
    raw_out  = nmap_result.get("output", "")
    filename = f"{REPORT_DIR}/nmap_{target.replace('.', '_')}_{ts}.md"

    cve_results: list = nmap_result.get("_cve_results", [])

    # ── Risk summary ──────────────────────────────────────────────────────────
    overall_risk, risk_reason = _nmap_risk(nmap_result, cve_results)
    status_icon = "✅" if nmap_result["success"] else "❌"

    lines = [
        "# Nmap Scan Report",
        "",
        "## Risk Summary",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Target**     | `{target}` |",
        f"| **Scan Status**| {status_icon} {'Success' if nmap_result['success'] else 'Failed'} |",
        f"| **Timestamp**  | {ts} |",
        f"| **Overall Risk** | {overall_risk} |",
        f"| **Risk Reason**  | {risk_reason} |",
        "",
    ]

    # ── Parsed port table ─────────────────────────────────────────────────────
    ports = _parse_ports(raw_out)
    host_info = _parse_host_info(raw_out)

    # ── Attack surface summary ─────────────────────────────────────────────────
    lines += _attack_surface_summary(ports, host_info)

    if host_info:
        lines += [
            "## Host Information",
            "",
            f"| Field | Value |",
            f"|---|---|",
        ]
        for k, v in host_info.items():
            lines.append(f"| **{k}** | {v} |")
        lines.append("")

    if ports:
        lines += [
            "## Open Ports & Services",
            "",
            "| Port | State | Service | Version | Sev | Note |",
            "|---|---|---|---|---|---|",
        ]
        for p in ports:
            state_icon      = "🟢" if p["state"] == "open" else "🟡"
            sev_icon, sev_note = _port_severity(p["port"])
            ver_warn        = _check_vulnerable_version(p["service"], p["version"])
            note_col        = ver_warn or sev_note or "—"
            lines.append(
                f"| `{p['port']}` | {state_icon} {p['state']} "
                f"| {p['service']} | {p['version'] or '—'} "
                f"| {sev_icon or '—'} | {note_col} |"
            )
        lines.append("")

    # ── CVE findings ──────────────────────────────────────────────────────────
    if cve_results:
        lines += [
            "## CVE Findings",
            "",
        ]
        total_cves = sum(len(r.cves) for r in cve_results)
        lines.append(
            f"> **{total_cves} CVE(s)** found across "
            f"{sum(1 for r in cve_results if r.cves)} service(s).\n"
        )

        for svc_result in cve_results:
            port_label = f"Port {svc_result.port}/{svc_result.protocol}"
            svc_label  = f"{svc_result.product} {svc_result.version}".strip() or svc_result.service

            if not svc_result.cves:
                lines += [
                    f"### 🟢 {port_label} — {svc_label}",
                    "",
                    "_No CVEs found._",
                    "",
                ]
                continue

            # Highest severity for this service
            top_severity = _top_severity(svc_result.cves)
            sev_icon     = _severity_icon(top_severity)

            lines += [
                f"### {sev_icon} {port_label} — {svc_label}",
                "",
                "| CVE ID | CVSS | Severity | Published | Description |",
                "|---|---|---|---|---|",
            ]
            for cve in svc_result.cves:
                cvss      = getattr(cve, "cvss_score", "N/A")
                severity  = getattr(cve, "severity",   "N/A")
                published = getattr(cve, "published",  "N/A")
                desc      = getattr(cve, "description", "")
                short_desc = (desc[:120] + "…") if len(desc) > 120 else desc
                lines.append(
                    f"| `{cve.cve_id}` | {cvss} | {severity} "
                    f"| {published} | {short_desc} |"
                )
            lines.append("")

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = _nmap_recommendations(ports, cve_results)
    if recs:
        lines += ["## Recommendations", ""]
        lines += [f"- {r}" for r in recs]
        lines.append("")

    # ── Raw output (collapsible) ──────────────────────────────────────────────
    lines += [
        "## Raw Nmap Output",
        "",
        "<details><summary>Show raw output</summary>",
        "",
        "```",
        raw_out.strip(),
        "```",
        "",
        "</details>",
    ]

    if nmap_result.get("error"):
        lines += ["", "## Errors", "", "```", nmap_result["error"].strip(), "```"]

    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    return filename


# ── AI Red-Team Report ────────────────────────────────────────────────────────

def generate_redteam_report(report) -> str:
    """
    Generate a Markdown report from an AIRedTeamTester RedTeamReport.
    Returns the file path of the saved report.
    """
    from ai_red_team.tester import RedTeamReport  # avoid circular import
    assert isinstance(report, RedTeamReport)

    _ensure_dir()
    ts = _timestamp()
    filename = f"{REPORT_DIR}/redteam_{report.target_name}_{ts}.md"

    risk = _risk_label(report.success_rate)
    lines = [
        f"# AI Red-Team Security Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Target AI** | {report.target_name} |",
        f"| **Timestamp** | {ts} |",
        f"| **Total Attacks** | {len(report.results)} |",
        f"| **Bypassed** | {len(report.successful_attacks)} |",
        f"| **Bypass Rate** | {report.success_rate:.0%} |",
        f"| **Risk Level** | {risk} |",
        f"",
        f"## Executive Summary",
        f"",
        _executive_summary(report),
        f"",
        f"## Attack Results",
        f"",
    ]

    for r in report.results:
        icon = "🔴" if r.success else "🟢"
        lines += [
            f"### {icon} {r.attack_name}",
            f"",
            f"- **Category:** {r.category}",
            f"- **Outcome:** {'BYPASSED ⚠️' if r.success else 'Blocked ✅'}",
            f"- **What it tests:** {r.notes}",
            f"",
            f"<details><summary>Prompt sent</summary>",
            f"",
            f"```",
            r.prompt_sent,
            f"```",
            f"</details>",
            f"",
            f"<details><summary>Model response</summary>",
            f"",
            r.response,
            f"</details>",
            f"",
        ]

    lines += [
        f"## Recommendations",
        f"",
        *_recommendations(report),
    ]

    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    return filename


# ── Nmap helpers ──────────────────────────────────────────────────────────────

_PORT_SEVERITY: dict[int, tuple[str, str]] = {
    # 🔴 CRITICAL — plaintext / legacy / known backdoors
    21:    ("🔴", "FTP — plaintext credentials, often exploitable"),
    23:    ("🔴", "Telnet — unencrypted; replace with SSH"),
    69:    ("🔴", "TFTP — unauthenticated file transfer"),
    79:    ("🔴", "Finger — user enumeration"),
    512:   ("🔴", "rexec — remote exec, no encryption"),
    513:   ("🔴", "rlogin — legacy remote login"),
    514:   ("🔴", "rsh — remote shell, no authentication"),
    # 🟠 HIGH — remote management / SMB / exposed databases
    25:    ("🟠", "SMTP — verify relay is not open"),
    110:   ("🟠", "POP3 — plaintext mail retrieval"),
    143:   ("🟠", "IMAP — plaintext mail retrieval"),
    161:   ("🟠", "SNMP — often misconfigured, information leakage"),
    135:   ("🟠", "MSRPC — Windows RPC, restrict from internet"),
    139:   ("🟠", "NetBIOS — legacy Windows file sharing"),
    445:   ("🟠", "SMB — high-value target (EternalBlue, ransomware)"),
    3389:  ("🟠", "RDP — brute-force / BlueKeep target"),
    5900:  ("🟠", "VNC — remote desktop, often weak auth"),
    # 🟡 MEDIUM — databases / internal services
    3306:  ("🟡", "MySQL — database should not be internet-facing"),
    5432:  ("🟡", "PostgreSQL — database should not be internet-facing"),
    6379:  ("🟡", "Redis — often unauthenticated by default"),
    27017: ("🟡", "MongoDB — often unauthenticated by default"),
    9200:  ("🟡", "Elasticsearch — often unauthenticated by default"),
    2181:  ("🟡", "Zookeeper — no authentication by default"),
    11211: ("🟡", "Memcached — no auth, amplification DDoS vector"),
    # 🔵 INFO — common services worth noting
    22:   ("🔵", "SSH — ensure key-based auth, disable root login"),
    80:   ("🔵", "HTTP — check if HTTPS is also available"),
    8080: ("🔵", "HTTP-alt — often dev/proxy, verify exposure"),
    8443: ("🔵", "HTTPS-alt — verify certificate validity"),
}

_VULNERABLE_VERSIONS = [
    # (service_keyword, version_keyword, warning)
    ("apache", "2.4.49",  "CVE-2021-41773 — Path Traversal/RCE (CVSS 9.8)"),
    ("apache", "2.4.50",  "CVE-2021-42013 — Path Traversal/RCE bypass (CVSS 9.8)"),
    ("apache", "2.2.",    "EOL since 2018 — no security patches"),
    ("vsftpd", "2.3.4",   "CVE-2011-2523 — Backdoor, instant root shell"),
    ("proftpd","1.3.5",   "CVE-2015-3306 — Remote code execution"),
    ("openssl","0.",      "EOL — numerous critical CVEs"),
    ("openssl","1.0.",    "EOL since 2020 — no security patches"),
    ("openssl","1.1.0",   "EOL since 2019 — no security patches"),
    ("php",    "5.",      "EOL since 2019 — no security patches"),
    ("php",    "7.0",     "EOL since 2019 — no security patches"),
    ("php",    "7.1",     "EOL since 2019 — no security patches"),
    ("php",    "7.2",     "EOL since 2020 — no security patches"),
    ("php",    "7.3",     "EOL since 2021 — no security patches"),
    ("iis",    "6.0",     "EOL — CVE-2017-7269 Buffer Overflow RCE"),
    ("iis",    "7.0",     "EOL — no security patches"),
    ("openssh","3.",      "Multiple critical CVEs — upgrade immediately"),
    ("openssh","4.",      "Multiple critical CVEs — upgrade immediately"),
    ("openssh","5.",      "Multiple CVEs — upgrade recommended"),
    ("openssh","6.",      "Multiple CVEs — upgrade recommended"),
    ("samba",  "3.",      "CVE-2017-7494 — SambaCry RCE"),
    ("samba",  "4.0",     "Multiple RCE CVEs — upgrade immediately"),
    ("redis",  "2.",      "EOL — numerous CVEs"),
    ("redis",  "3.",      "EOL — numerous CVEs"),
]


def _port_severity(port_str: str) -> tuple[str, str]:
    """Return (icon, note) for a port string like '22/tcp'. Empty strings if unknown."""
    try:
        port_num = int(port_str.split("/")[0])
    except ValueError:
        return "", ""
    return _PORT_SEVERITY.get(port_num, ("", ""))


def _check_vulnerable_version(service: str, version: str) -> str:
    """Return a warning string if the service+version matches a known-vulnerable pattern."""
    if not version:
        return ""
    combined = f"{service.lower()} {version.lower()}"
    for svc_kw, ver_kw, warning in _VULNERABLE_VERSIONS:
        if svc_kw in combined and ver_kw in combined:
            return f"⚠ {warning}"
    return ""


def _attack_surface_summary(ports: list, host_info: dict) -> list[str]:
    open_ports     = [p for p in ports if p["state"] == "open"]
    filtered_ports = [p for p in ports if p["state"] == "filtered"]
    protocols      = sorted({p["port"].split("/")[1] for p in open_ports}) if open_ports else []
    services       = sorted({p["service"] for p in open_ports if p["service"] not in ("unknown", "tcpwrapped")})

    risky    = [(p, *_port_severity(p["port"])) for p in open_ports]
    critical = [(p, note) for p, icon, note in risky if icon == "🔴"]
    high     = [(p, note) for p, icon, note in risky if icon == "🟠"]
    medium   = [(p, note) for p, icon, note in risky if icon == "🟡"]

    lines = [
        "## Attack Surface Summary",
        "",
        "| | |",
        "|---|---|",
        f"| **Open Ports**     | {len(open_ports)} |",
        f"| **Filtered Ports** | {len(filtered_ports)} |",
        f"| **Protocols**      | {', '.join(protocols) if protocols else '—'} |",
        f"| **Services**       | {', '.join(services[:8]) if services else '—'} |",
    ]
    if critical:
        names = ", ".join(f"`{p['port']}`" for p, _ in critical)
        lines.append(f"| **🔴 Critical Ports** | {names} |")
    if high:
        names = ", ".join(f"`{p['port']}`" for p, _ in high)
        lines.append(f"| **🟠 High-Risk Ports** | {names} |")
    if medium:
        names = ", ".join(f"`{p['port']}`" for p, _ in medium)
        lines.append(f"| **🟡 Medium-Risk Ports** | {names} |")
    lines.append("")
    return lines


def _parse_ports(raw: str) -> list[dict]:
    """Extract port rows from nmap -sV output."""
    ports = []
    # Use [ \t] instead of \s to avoid consuming newlines between port rows
    pattern = re.compile(
        r"^(\d+/\w+)[ \t]+(open|filtered|closed)[ \t]+(\S+)[ \t]*(.*?)[ \t]*$",
        re.MULTILINE,
    )
    for m in pattern.finditer(raw):
        ports.append({
            "port":    m.group(1),
            "state":   m.group(2),
            "service": m.group(3),
            "version": m.group(4).strip(),
        })
    return ports


def _parse_host_info(raw: str) -> dict:
    """Extract host-level metadata from nmap output."""
    info = {}
    ip_match  = re.search(r"Nmap scan report for .+?\((\d+\.\d+\.\d+\.\d+)\)", raw)
    lat_match = re.search(r"Host is up \(([^)]+)\)", raw)
    os_match  = re.search(r"Service Info:.*?OS:\s*([^;,\n]+)", raw)
    dur_match = re.search(r"scanned in ([\d.]+ seconds)", raw)

    if ip_match:
        info["IP Address"] = ip_match.group(1)
    if lat_match:
        info["Latency"] = lat_match.group(1)
    if os_match:
        info["Detected OS"] = os_match.group(1).strip()
    if dur_match:
        info["Scan Duration"] = dur_match.group(1)
    return info


def _top_severity(cves: list) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0, "N/A": 0}
    best  = "None"
    for cve in cves:
        sev = getattr(cve, "severity", "None") or "None"
        if order.get(sev, 0) > order.get(best, 0):
            best = sev
    return best


def _severity_icon(severity: str) -> str:
    return {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🔵",
    }.get(severity, "🟢")


def _nmap_risk(nmap_result: dict, cve_results: list) -> tuple[str, str]:
    """Derive an overall risk label from CVE findings."""
    if not nmap_result["success"]:
        return "⚪ UNKNOWN", "Scan did not complete successfully"

    if not cve_results or not any(r.cves for r in cve_results):
        return "🟢 LOW", "No CVEs found"

    all_cves  = [c for r in cve_results for c in r.cves]
    severities = [getattr(c, "severity", "None") or "None" for c in all_cves]

    if "Critical" in severities:
        return "🔴 CRITICAL", f"{severities.count('Critical')} critical CVE(s) detected"
    if "High" in severities:
        return "🟠 HIGH", f"{severities.count('High')} high-severity CVE(s) detected"
    if "Medium" in severities:
        return "🟡 MEDIUM", f"{severities.count('Medium')} medium-severity CVE(s) detected"
    return "🔵 LOW", f"{len(all_cves)} low-severity CVE(s) detected"


def _nmap_recommendations(ports: list, cve_results: list) -> list[str]:
    recs = []
    open_ports = [p for p in ports if p["state"] == "open"]
    services   = {p["service"].lower() for p in open_ports}

    # ── Vulnerable version warnings ───────────────────────────────────────────
    for p in open_ports:
        warn = _check_vulnerable_version(p["service"], p["version"])
        if warn:
            recs.append(f"**{p['port']} ({p['service']}):** {warn}")

    # ── Critical port warnings ─────────────────────────────────────────────────
    for p in open_ports:
        icon, note = _port_severity(p["port"])
        if icon == "🔴":
            recs.append(f"**{p['port']} ({p['service']}):** {note} — disable or replace immediately.")

    # ── High-risk port warnings ────────────────────────────────────────────────
    for p in open_ports:
        icon, note = _port_severity(p["port"])
        if icon == "🟠":
            recs.append(f"**{p['port']} ({p['service']}):** {note}")

    # ── Service-specific hints ────────────────────────────────────────────────
    if "ssh" in services:
        recs.append("**SSH:** Ensure key-based auth only; disable root login; update to latest OpenSSH.")
    if "http" in services and "https" not in services:
        recs.append("**HTTP (no HTTPS):** Consider redirecting all traffic to HTTPS.")

    # ── CVE-based hints ───────────────────────────────────────────────────────
    if cve_results:
        cve_count = sum(len(r.cves) for r in cve_results)
        if cve_count:
            recs.append(
                f"**CVEs:** {cve_count} vulnerabilities found — review and patch affected services. "
                "Prioritise Critical and High severity entries."
            )

    if not recs:
        recs.append("No immediate critical issues. Schedule regular scans to monitor changes.")
    return recs


# ── Red-team helpers ──────────────────────────────────────────────────────────

def _risk_label(rate: float) -> str:
    if rate >= 0.7:
        return "🔴 CRITICAL"
    if rate >= 0.4:
        return "🟠 HIGH"
    if rate >= 0.2:
        return "🟡 MEDIUM"
    return "🟢 LOW"


def _executive_summary(report) -> str:
    if not report.successful_attacks:
        return (
            f"The target model **{report.target_name}** successfully blocked all "
            f"{len(report.results)} adversarial prompts. No bypass was detected."
        )
    cats = {r.category for r in report.successful_attacks}
    return (
        f"**{len(report.successful_attacks)} out of {len(report.results)} attacks "
        f"bypassed the model's safety measures**, representing a "
        f"{report.success_rate:.0%} bypass rate.\n\n"
        f"Vulnerable attack categories: **{', '.join(sorted(cats))}**."
    )


def _recommendations(report) -> list[str]:
    recs = []
    cats = {r.category for r in report.successful_attacks}
    if "jailbreak" in cats:
        recs.append("- **Jailbreak:** Strengthen system-prompt instructions; consider Constitutional AI fine-tuning.")
    if "injection" in cats:
        recs.append("- **Prompt Injection:** Sanitize or isolate user input from system context.")
    if "extraction" in cats:
        recs.append("- **Data Extraction:** Use a non-revealing system prompt; implement output filters.")
    if "confusion" in cats:
        recs.append("- **Confusion / Obfuscation:** Add Unicode normalisation before tokenisation.")
    if "authority" in cats:
        recs.append("- **Authority Claims:** Never execute instructions that claim developer/admin status.")
    if not recs:
        recs.append("- No critical issues found. Continue regular red-team assessments.")
    return recs


# ── Gobuster helpers ──────────────────────────────────────────────────────────

_HIGH_INTEREST_PATHS = {
    "admin", "administrator", "backup", "backups", "config", "configuration",
    ".git", ".env", ".htaccess", ".htpasswd", "secret", "secrets",
    "password", "passwords", "passwd", "credentials", "credential",
    "token", "tokens", "key", "keys", "private", "internal",
    "api", "debug", "test", "tests", "dev", "staging", "phpmyadmin",
    "wp-admin", "wp-login", "console", "dashboard", "panel",
    "database", "db", "sql", "shell", "upload", "uploads",
    "tmp", "temp", "cache", "logs", "log", "hidden", "old", "bak",
}


def _path_severity(path: str) -> str:
    lower = path.lower()
    for keyword in _HIGH_INTEREST_PATHS:
        if keyword in lower:
            return "🔴 HIGH"
    return ""


def _size_note(size: int) -> str:
    if size == 0:
        return "Empty response"
    if size < 50:
        return "⚠ Suspiciously small"
    if size > 100_000:
        return "Large page"
    return ""


# ── Gobuster Report ───────────────────────────────────────────────────────────

def generate_gobuster_report(result) -> str:
    """
    Generate a Markdown report from a GobusterResult object.
    Returns the file path of the saved .md report.
    """
    _ensure_dir()
    ts       = _timestamp()
    safe     = result.target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{REPORT_DIR}/gobuster_{safe}_{ts}.md"

    total     = len(result.findings)
    found     = len(result.found_paths)
    redirects = len(result.redirect_paths)
    status    = "✅ Success" if result.success or result.findings else "❌ Failed"

    lines = [
        "# Gobuster Directory Scan Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Target**     | `{result.target}` |",
        f"| **Status**     | {status} |",
        f"| **Timestamp**  | {ts} |",
        f"| **Total Found**| {total} |",
        f"| **Accessible** | {found} |",
        f"| **Redirects**  | {redirects} |",
        "",
    ]

    # ── Wildcard notice ───────────────────────────────────────────────────────
    wc = getattr(result, "wildcard_excluded", "")
    if wc:
        lines += [
            "> ⚠ **Wildcard detected** — the server returned HTTP 200 for non-existing URLs "
            f"(response size: **{wc}B**). Scan was automatically re-run with "
            f"`--exclude-length {wc}` to filter out false positives.",
            "",
        ]

    # ── Discovered paths ──────────────────────────────────────────────────────
    if result.interesting_paths:
        high_interest = [f for f in result.interesting_paths if _path_severity(f.path)]

        if high_interest:
            lines += [
                "## High-Interest Paths",
                "",
                "| Severity | Path | Status | Size | Note | Redirect |",
                "|---|---|---|---|---|---|",
            ]
            for f in high_interest:
                note = _size_note(f.size)
                lines.append(
                    f"| 🔴 HIGH | `{f.path}` | {f.status} "
                    f"| {f.size}B | {note or '—'} | {f.redirect or '—'} |"
                )
            lines.append("")

        lines += [
            "## All Discovered Paths",
            "",
            "| | Path | Status | Size | Note | Redirect |",
            "|---|---|---|---|---|---|",
        ]
        for f in result.interesting_paths:
            icon     = "🟢" if f.status == 200 else "🟡"
            severity = _path_severity(f.path)
            note     = _size_note(f.size)
            path_col = f"`{f.path}`" + (f" ← {severity}" if severity else "")
            lines.append(
                f"| {icon} | {path_col} | {f.status} "
                f"| {f.size}B | {note or '—'} | {f.redirect or '—'} |"
            )
        lines.append("")
    else:
        lines += ["_No paths discovered._", ""]

    # ── Recommendations ───────────────────────────────────────────────────────
    if result.findings:
        recs = []
        high_paths = [f for f in result.interesting_paths if _path_severity(f.path)]
        if high_paths:
            names = ", ".join(f"`{f.path}`" for f in high_paths[:5])
            recs.append(
                f"**Sensitive paths found** — {names} may expose admin interfaces, "
                "credentials, or source control data. Investigate and restrict access immediately."
            )
        if any(f.status == 200 for f in result.interesting_paths):
            recs.append("**Accessible paths found** — review each for unintended exposure.")
        if redirects:
            recs.append("**Redirects detected** — verify redirect targets are intentional.")
        small = [f for f in result.interesting_paths if 0 < f.size < 50]
        if small:
            recs.append(
                f"**Suspiciously small responses** ({len(small)} path(s)) — "
                "may indicate honeypots or partial content; verify manually."
            )
        if wc:
            recs.append(
                f"**Wildcard responses excluded** (size {wc}B) — results may still contain "
                "noise if the server uses multiple wildcard sizes."
            )
        if recs:
            lines += ["## Recommendations", ""] + [f"- {r}" for r in recs] + [""]

    if getattr(result, "error", None):
        lines += ["## Errors", "", "```", result.error.strip(), "```"]

    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    return filename