"""
reports/report_generator.py
Converts scan results into professional PDF security reports.
Pipeline: Markdown content → HTML (via markdown2) → PDF (via xhtml2pdf).
"""
import os
import re
import io
import datetime
import markdown2
from xhtml2pdf import pisa
from config import REPORT_DIR


# ── PDF styling ───────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {{ margin: 20mm 16mm; }}
  body {{ font-family: Helvetica, Arial, sans-serif; font-size: 10pt;
         color: #1a1a1a; margin: 0; padding: 0; line-height: 1.45; }}
  /* ── Cover header ─────────────────────────────────────────────────────── */
  .rpt-header {{ background: #1a1a1a; color: white; padding: 14px 18px 12px 18px;
                 margin-bottom: 20px; }}
  .rpt-title  {{ color: #e74c3c; font-size: 22pt; font-weight: bold;
                 margin: 0 0 3px 0; }}
  .rpt-sub    {{ color: #aaaaaa; font-size: 8.5pt; margin: 0; }}
  /* ── Headings ─────────────────────────────────────────────────────────── */
  h1 {{ color: #c0392b; font-size: 16pt; border-bottom: 2px solid #c0392b;
        padding-bottom: 4px; margin-top: 20px; margin-bottom: 8px; }}
  h2 {{ color: #c0392b; font-size: 12.5pt; border-bottom: 1px solid #dddddd;
        padding-bottom: 3px; margin-top: 16px; margin-bottom: 6px; }}
  h3 {{ color: #333333; font-size: 11pt; margin-top: 13px; margin-bottom: 4px; }}
  h4 {{ color: #555555; font-size: 10pt; margin-top: 10px; margin-bottom: 3px; }}
  /* ── Tables ───────────────────────────────────────────────────────────── */
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 9pt; }}
  th {{ background-color: #c0392b; color: white; padding: 5px 8px;
        text-align: left; font-weight: bold; }}
  td {{ padding: 4px 8px; border-bottom: 1px solid #e5e5e5;
        vertical-align: top; word-wrap: break-word; }}
  tr.even td {{ background-color: #f8f8f8; }}
  /* ── Code ─────────────────────────────────────────────────────────────── */
  code {{ background-color: #f0f0f0; padding: 1px 3px; font-size: 8.5pt;
          font-family: Courier New, Courier, monospace; }}
  pre  {{ background-color: #f0f0f0; padding: 8px 10px; font-size: 8pt;
          font-family: Courier New, Courier, monospace; white-space: pre-wrap;
          word-wrap: break-word; border-left: 3px solid #c0392b; margin: 6px 0; }}
  /* ── Blockquote ───────────────────────────────────────────────────────── */
  blockquote {{ border-left: 4px solid #c0392b; margin: 6px 0;
                padding: 5px 12px; background-color: #fdf2f2; font-size: 9.5pt; }}
  /* ── Links ────────────────────────────────────────────────────────────── */
  a {{ color: #c0392b; text-decoration: none; word-wrap: break-word; }}
  /* ── Misc ─────────────────────────────────────────────────────────────── */
  p  {{ margin: 4px 0 7px 0; }}
  li {{ margin-bottom: 2px; }}
  hr {{ border: none; border-top: 1px solid #dddddd; margin: 12px 0; }}
</style>
</head>
<body>
<div class="rpt-header">
  <div class="rpt-title">FENRIR</div>
  <div class="rpt-sub">Flexible Engine for Network Reconnaissance &amp; Intelligent Red-teaming</div>
</div>
{body}
</body>
</html>"""

# ── Two-step emoji replacement ────────────────────────────────────────────────
#
# Problem: inserting HTML tags (<b class="...">) into Markdown source breaks
# markdown2's inline parser when the tag sits inside **bold** markers, producing
# malformed HTML and xhtml2pdf rendering artefacts (black boxes, squished text).
#
# Fix: replace emoji with plain-text tokens FIRST (step 1, before markdown2),
# then swap tokens for coloured HTML badges AFTER markdown→HTML conversion
# (step 2), so the markdown parser never sees raw HTML tags in table cells.

# Step 1 -- emoji -> plain ASCII tokens (markdown-safe, no HTML)
# All keys use \uXXXX escapes to avoid quote-normalisation issues.
_EMOJI_TOKENS = {
    '\U0001f534': 'FENRIR_CRIT',   # red circle
    '\U0001f7e0': 'FENRIR_HIGH',   # orange circle
    '\U0001f7e1': 'FENRIR_MED',    # yellow circle
    '\U0001f535': 'FENRIR_LOW',    # blue circle
    '\U0001f7e2': 'FENRIR_OK',     # green circle
    '\u2705': 'FENRIR_YES',        # check mark button
    '\u274c': 'FENRIR_NO',         # cross mark
    '\u26a0\ufe0f': 'FENRIR_WARN', # warning sign + VS16
    '\u26a0': 'FENRIR_WARN',       # warning sign
    '\U0001f43a': 'FENRIR',        # wolf
    '\U0001f527': '',              # wrench
    '\u2713': 'OK',                # check mark
    '\u2717': 'FAIL',              # ballot x
    '\u2192': '->',               # rightwards arrow
    '\u2190': '<-',               # leftwards arrow
    '\u2014': '--',               # em dash
    '\u2013': '-',                # en dash
    '\u201c': '"',               # left double quotation mark
    '\u201d': '"',               # right double quotation mark
    '\u2018': chr(39),              # left single quotation mark
    '\u2019': chr(39),              # right single quotation mark
    '\u2026': '...',             # horizontal ellipsis
}

# Step 2 -- tokens -> coloured HTML badges (applied after markdown->HTML)
_TOKEN_HTML = {
    'FENRIR_CRIT': '<b style="color:#c0392b">[CRIT]</b>',
    'FENRIR_HIGH': '<b style="color:#e67e22">[HIGH]</b>',
    'FENRIR_MED':  '<b style="color:#d4a017">[MED]</b>',
    'FENRIR_LOW':  '<b style="color:#2980b9">[LOW]</b>',
    'FENRIR_OK':   '<b style="color:#27ae60">[OK]</b>',
    'FENRIR_YES':  '<b style="color:#27ae60">[YES]</b>',
    'FENRIR_NO':   '<b style="color:#c0392b">[NO]</b>',
    'FENRIR_WARN': '<b style="color:#e67e22">[!]</b>',
}


def _replace_emoji(text: str) -> str:
    """
    Step 1: replace emoji/special chars with plain-text tokens.
    Any char outside Latin Extended-B that has no token is replaced with '?'
    so xhtml2pdf never encounters an unknown glyph.
    """
    for emoji, token in _EMOJI_TOKENS.items():
        text = text.replace(emoji, token)
    result = []
    for ch in text:
        cp = ord(ch)
        if cp <= 0x024F:                    # Basic Latin + Latin Extended A/B
            result.append(ch)
        elif 0x0370 <= cp <= 0x03FF:        # Greek (appears in some CVE text)
            result.append(ch)
        else:
            result.append("?")
    return "".join(result)


def _md_to_pdf(md_content: str, pdf_path: str) -> bool:
    """
    Convert Markdown string to a styled PDF file.

    Pipeline:
      1. _replace_emoji()  — emoji → plain tokens  (before markdown parsing)
      2. strip details/summary tags
      3. markdown2          — Markdown → HTML
      4. _TOKEN_HTML swap   — tokens → coloured badges (after markdown parsing)
      5. _stripe_tables()  — alternating row colours
      6. xhtml2pdf          — HTML → PDF
    """
    # 1. Emoji → plain-text tokens
    md_content = _replace_emoji(md_content)

    # 2. Strip non-interactive HTML wrappers
    md_clean = re.sub(r"<details[^>]*>", "", md_content)
    md_clean = re.sub(r"</details>", "", md_clean)
    md_clean = re.sub(r"<summary[^>]*>.*?</summary>", "\n**Details:**\n",
                      md_clean, flags=re.DOTALL)

    # 3. Markdown → HTML
    html_body = markdown2.markdown(
        md_clean,
        extras=["tables", "fenced-code-blocks", "strike", "header-ids"],
    )

    # 4. Tokens → coloured HTML badges (safe: markdown already parsed)
    for token, badge in _TOKEN_HTML.items():
        html_body = html_body.replace(token, badge)

    # 5. Force 38/62% column widths on 2-column summary tables
    html_body = _fix_table_widths(html_body)

    # 6. Alternate table row colours (nth-child not supported by xhtml2pdf)
    html_body = _stripe_tables(html_body)

    html = _HTML_TEMPLATE.format(body=html_body)

    # 6. Render to PDF
    try:
        with open(pdf_path, "wb") as f:
            result = pisa.CreatePDF(io.StringIO(html), dest=f, encoding="utf-8")
        return not result.err
    except Exception as exc:
        from logger import warn
        warn(f"PDF generation failed: {exc}")
        return False


def _stripe_tables(html: str) -> str:
    """Add alternating 'even' class to every second <tr> for PDF table styling."""
    lines = html.split("\n")
    out = []
    tr_count = 0
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("<tr"):
            tr_count += 1
            if tr_count % 2 == 0:
                line = line.replace("<tr>", '<tr class="even">', 1)
        if stripped.startswith("</table"):
            tr_count = 0
        out.append(line)
    return "\n".join(out)


def _fix_table_widths(html: str) -> str:
    """
    For 2-column summary tables: inject width="38%" / width="62%" on every
    cell so xhtml2pdf never under-sizes the label column.
    Tables with 3+ columns are left untouched (auto-sizing works fine there).
    """
    def fix_table(m: re.Match) -> str:
        table_html = m.group(0)
        first_tr = re.search(r'<tr[^>]*>.*?</tr>', table_html, re.DOTALL)
        if not first_tr:
            return table_html
        col_count = len(re.findall(r'<t[dh][^>]*>', first_tr.group(0)))
        if col_count != 2:
            return table_html

        widths = ['38%', '62%']

        def fix_row(row_m: re.Match) -> str:
            row = row_m.group(0)
            idx = [0]

            def fix_cell(cell_m: re.Match) -> str:
                tag = cell_m.group(0)
                if idx[0] < 2:
                    w = widths[idx[0]]
                    idx[0] += 1
                    return tag[:-1] + f' width="{w}">'
                return tag

            return re.sub(r'<(td|th)[^>]*>', fix_cell, row)

        return re.sub(r'<tr[^>]*>.*?</tr>', fix_row, table_html, flags=re.DOTALL)

    return re.sub(r'<table[^>]*>.*?</table>', fix_table, html, flags=re.DOTALL)


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
    filename = f"{REPORT_DIR}/nmap_{target.replace('.', '_')}_{ts}.pdf"

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
                severity  = getattr(cve, "cvss_severity", "N/A")
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

    _md_to_pdf("\n".join(lines), filename)

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
    filename = f"{REPORT_DIR}/redteam_{report.target_name}_{ts}.pdf"

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

    _md_to_pdf("\n".join(lines), filename)
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
        sev = getattr(cve, "cvss_severity", "None") or "None"
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
    severities = [getattr(c, "cvss_severity", "None") or "None" for c in all_cves]

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
    filename = f"{REPORT_DIR}/gobuster_{safe}_{ts}.pdf"

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

    _md_to_pdf("\n".join(lines), filename)
    return filename


# ── CORS Report ──────────────────────────────────────────────────────────────

def generate_cors_report(result) -> str:
    """Generate a PDF report from a CORSResult object."""
    _ensure_dir()
    ts   = _timestamp()
    safe = result.target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{REPORT_DIR}/cors_{safe}_{ts}.pdf"

    sev_icon = {
        "Critical": "🔴 CRITICAL",
        "High":     "🟠 HIGH",
        "Medium":   "🟡 MEDIUM",
        "Low":      "🔵 LOW",
        "None":     "🟢 NONE",
    }.get(result.worst_severity, "🟢 NONE")

    lines = [
        "# CORS Misconfiguration Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Target URL**  | `{result.target}` |",
        f"| **Status**      | {'Success' if result.success else 'Failed'} |",
        f"| **Findings**    | {len(result.findings)} |",
        f"| **Risk Level**  | {sev_icon} |",
        f"| **Timestamp**   | {ts} |",
        "",
    ]

    if result.error and not result.findings:
        lines += ["## Error", "", f"> {result.error}", ""]

    if result.findings:
        lines += [
            "## Findings",
            "",
            "| Severity | Origin Sent | ACAO Header | ACAC | Detail |",
            "|---|---|---|---|---|",
        ]
        for f in result.findings:
            sev_label = {
                "Critical": "🔴 Critical",
                "High":     "🟠 High",
                "Medium":   "🟡 Medium",
                "Low":      "🔵 Low",
            }.get(f.severity, f.severity)
            lines.append(
                f"| {sev_label} | `{f.origin_sent}` | `{f.acao_header}` "
                f"| {f.acac_header} | {f.detail[:100]}... |"
            )
        lines.append("")

        lines += ["## Detailed Findings", ""]
        for i, f in enumerate(result.findings, 1):
            lines += [
                f"### Finding {i} — {f.severity}",
                "",
                f"**Origin sent:** `{f.origin_sent}`  ",
                f"**Access-Control-Allow-Origin:** `{f.acao_header}`  ",
                f"**Access-Control-Allow-Credentials:** `{f.acac_header}`  ",
                "",
                f"**Impact:** {f.detail}",
                "",
            ]

        lines += [
            "## Remediation",
            "",
            "- **Never reflect the `Origin` header directly** — maintain an explicit allowlist of trusted origins.",
            "- **Never use `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`** — browsers block it but it signals misconfiguration.",
            "- **Reject the `null` origin** — it provides no meaningful security guarantee and is abusable via sandboxed iframes.",
            "- Implement server-side allowlist validation:",
            "",
            "```python",
            "ALLOWED_ORIGINS = {'https://app.yourdomain.com', 'https://admin.yourdomain.com'}",
            "origin = request.headers.get('Origin', '')",
            "if origin in ALLOWED_ORIGINS:",
            "    response.headers['Access-Control-Allow-Origin'] = origin",
            "    response.headers['Vary'] = 'Origin'",
            "```",
            "",
        ]
    else:
        lines += [
            "## Result",
            "",
            "No CORS misconfiguration detected. The server does not reflect",
            "untrusted origins or does not include permissive CORS headers.",
            "",
        ]

    _md_to_pdf("\n".join(lines), filename)
    return filename


# ── Takeover Report ──────────────────────────────────────────────────────────

def generate_takeover_report(result) -> str:
    """Generate a PDF report from a TakeoverResult object."""
    _ensure_dir()
    ts   = _timestamp()
    safe = result.target.replace(".", "_")
    filename = f"{REPORT_DIR}/takeover_{safe}_{ts}.pdf"

    status_icon = "✅" if result.success else "❌"
    risk = "🔴 CRITICAL" if result.high_confidence else ("🟠 HIGH" if result.has_findings else "🟢 NONE")

    lines = [
        "# Subdomain Takeover Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Target**           | `{result.target}` |",
        f"| **Status**           | {status_icon} {'Success' if result.success else 'Failed'} |",
        f"| **Subdomains Checked** | {result.checked} |",
        f"| **Vulnerable**       | {len(result.vulnerable)} |",
        f"| **Risk Level**       | {risk} |",
        f"| **Timestamp**        | {ts} |",
        "",
    ]

    if result.vulnerable:
        lines += [
            "## Vulnerable Subdomains",
            "",
            "> These subdomains have dangling CNAME records pointing to unclaimed",
            "> external services. An attacker can register the service and serve",
            "> arbitrary content under your domain.",
            "",
            "| Confidence | Subdomain | CNAME Target | Service | Indicator |",
            "|---|---|---|---|---|",
        ]
        for f in result.vulnerable:
            conf_icon = "🔴" if f.confidence == "High" else "🟠"
            lines.append(
                f"| {conf_icon} {f.confidence} | `{f.subdomain}` "
                f"| `{f.cname}` | {f.service} | {f.indicator[:60]} |"
            )
        lines += [
            "",
            "## Remediation",
            "",
            "For each vulnerable subdomain, choose one of:",
            "",
            "1. **Remove the DNS record** — if the subdomain is no longer needed, "
               "delete the CNAME entry from your DNS provider.",
            "2. **Reclaim the service** — create a new account/repository/bucket on "
               "the target platform and point it to this subdomain.",
            "3. **Replace with a redirect** — point the subdomain to an active service "
               "to close the window of opportunity.",
            "",
            "**Priority:** Fix High-confidence findings within 24 hours — they are "
            "confirmed exploitable and can be discovered by automated scanners.",
            "",
        ]
    else:
        lines += [
            "## Result",
            "",
            f"No subdomain takeover vulnerabilities detected across "
            f"{result.checked} subdomain(s).",
            "",
            "_Note: This check covers known fingerprints. New or custom services may_",
            "_not be detected. Manual review of unusual CNAME targets is recommended._",
            "",
        ]

    if result.error:
        lines += ["## Errors", "", f"> {result.error}", ""]

    _md_to_pdf("\n".join(lines), filename)
    return filename


# ── Subdomain Report ─────────────────────────────────────────────────────────

def generate_subdomain_report(result) -> str:
    """Generate a PDF report from a SubdomainResult object."""
    _ensure_dir()
    ts   = _timestamp()
    safe = result.target.replace(".", "_")
    filename = f"{REPORT_DIR}/subdomain_{safe}_{ts}.pdf"

    status_icon = "✅" if result.success else "❌"
    lines = [
        "# Subdomain Enumeration Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Target Domain** | `{result.target}` |",
        f"| **Status**        | {status_icon} {'Success' if result.success else 'Failed'} |",
        f"| **Source**        | {result.source} |",
        f"| **Timestamp**     | {ts} |",
        f"| **Subdomains**    | {result.count} |",
        "",
    ]

    if result.error:
        lines += ["## Error", "", f"> {result.error}", ""]

    if result.interesting:
        lines += [
            "## High-Interest Subdomains",
            "",
            "> These subdomains commonly indicate sensitive services (admin, API, dev, staging, etc.).",
            "",
            "| Subdomain |",
            "|---|",
        ]
        for sub in result.interesting:
            lines.append(f"| `{sub}` |")
        lines.append("")

    if result.subdomains:
        lines += [
            "## All Discovered Subdomains",
            "",
            "| # | Subdomain |",
            "|---|---|",
        ]
        for i, sub in enumerate(result.subdomains, 1):
            lines.append(f"| {i} | `{sub}` |")
        lines.append("")

        lines += [
            "## Recommendations",
            "",
            f"- **{result.count} subdomain(s) found.** Review each for unintended exposure.",
            "- Run a port scan (Nmap Full Scan) against newly discovered subdomains.",
            "- Check for subdomain takeover: CNAME records pointing to decommissioned services.",
            "- Pay special attention to: `dev.`, `api.`, `staging.`, `admin.`, `internal.`, `vpn.`",
        ]
        if result.interesting:
            lines.append(
                f"- **{len(result.interesting)} high-interest subdomain(s)** detected — "
                "prioritise these for further scanning."
            )
        lines.append("")
    else:
        lines += ["_No subdomains discovered._", ""]

    _md_to_pdf("\n".join(lines), filename)
    return filename


# ── Open Redirect Report ─────────────────────────────────────────────────────

def generate_redirect_report(result) -> str:
    """Generate a PDF report from a RedirectResult object."""
    _ensure_dir()
    ts   = _timestamp()
    safe = result.target.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{REPORT_DIR}/redirect_{safe}_{ts}.pdf"

    risk = "🔴 HIGH" if result.has_findings else "🟢 NONE"

    lines = [
        "# Open Redirect Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Target URL**  | `{result.target}` |",
        f"| **Status**      | {'Success' if result.success else 'Failed'} |",
        f"| **Findings**    | {len(result.findings)} |",
        f"| **Risk Level**  | {risk} |",
        f"| **Timestamp**   | {ts} |",
        "",
    ]

    if result.error and not result.findings:
        lines += ["## Error", "", f"> {result.error}", ""]

    if result.findings:
        lines += [
            "## Findings",
            "",
            "> The server issues a redirect to an attacker-controlled domain when",
            "> the listed parameters receive an external URL as their value.",
            "",
            "| Parameter | Payload | Status | Location Header |",
            "|---|---|---|---|",
        ]
        for f in result.findings:
            loc_trunc = f.location_header[:60] + ("..." if len(f.location_header) > 60 else "")
            lines.append(
                f"| `{f.parameter}` | `{f.payload}` | {f.status_code} | `{loc_trunc}` |"
            )
        lines.append("")

        lines += ["## Detailed Findings", ""]
        for i, f in enumerate(result.findings, 1):
            lines += [
                f"### Finding {i} — Parameter `{f.parameter}`",
                "",
                f"**Tested URL:** `{f.url_tested}`  ",
                f"**Payload:** `{f.payload}`  ",
                f"**HTTP Status:** {f.status_code}  ",
                f"**Location header:** `{f.location_header}`  ",
                "",
                "**Impact:** An attacker can craft a link to your application that "
                "silently forwards victims to a phishing or malware site. "
                "Because the link originates from a trusted domain it bypasses "
                "email filters and user vigilance.",
                "",
            ]

        lines += [
            "## Remediation",
            "",
            "- **Allowlist redirect destinations** — only permit redirects to a fixed set of "
            "trusted internal paths or domains.",
            "- **Reject absolute URLs in redirect parameters** — if only local redirects "
            "are needed, validate that the value starts with `/` and does not contain `://` or `//`.",
            "- **Use indirect references** — map redirect targets to opaque tokens server-side "
            "instead of accepting raw URLs from the client.",
            "",
            "Example safe redirect validation (Python):",
            "",
            "```python",
            "from urllib.parse import urlparse",
            "",
            "ALLOWED_HOSTS = {'app.yourdomain.com'}",
            "",
            "def safe_redirect(url: str, default: str = '/') -> str:",
            "    parsed = urlparse(url)",
            "    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:",
            "        return default",
            "    return url",
            "```",
            "",
        ]
    else:
        lines += [
            "## Result",
            "",
            "No open redirect vulnerabilities detected. The server did not issue",
            "external redirects in response to the tested parameters and payloads.",
            "",
            "_Note: This scan tests common parameter names. Custom or obfuscated_",
            "_parameter names may require manual testing._",
            "",
        ]

    _md_to_pdf("\n".join(lines), filename)
    return filename


# ── Full Scan Report ──────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


class _Finding:
    __slots__ = ("severity", "cvss", "category", "title", "context", "action")

    def __init__(self, severity, cvss, category, title, context, action):
        self.severity = severity
        self.cvss     = cvss
        self.category = category
        self.title    = title
        self.context  = context
        self.action   = action


def _collect_findings(full_result: dict) -> list[_Finding]:
    """Aggregate findings from all scan modules into a unified, sortable list."""
    findings: list[_Finding] = []
    ports     = _parse_ports(full_result.get("nmap_result", {}).get("output", ""))

    # ── CVEs ──────────────────────────────────────────────────────────────────
    for svc in full_result.get("cve_results", []):
        for cve in svc.cves:
            sev = cve.cvss_severity or "Unknown"
            findings.append(_Finding(
                severity=sev,
                cvss=cve.cvss_score,
                category="CVE",
                title=f"{cve.cve_id} — {cve.description[:80]}",
                context=f"Port {svc.port}/{svc.protocol} — {svc.product} {svc.version}".strip(),
                action=f"Patch / update {svc.product}. Details: {cve.url}",
            ))

    # ── Port risks ────────────────────────────────────────────────────────────
    for p in ports:
        if p["state"] != "open":
            continue
        icon, note = _port_severity(p["port"])
        sev = {"🔴": "Critical", "🟠": "High", "🟡": "Medium"}.get(icon)
        if sev:
            findings.append(_Finding(
                severity=sev,
                cvss=0.0,
                category="Port",
                title=f"Port {p['port']} ({p['service']}) — {note[:70]}",
                context=f"{p['service']} {p['version']}".strip(),
                action=note,
            ))

    # ── Known-vulnerable versions ─────────────────────────────────────────────
    for p in ports:
        warn_str = _check_vulnerable_version(p["service"], p["version"])
        if warn_str:
            sev = "Critical" if ("RCE" in warn_str or "9.8" in warn_str or "Backdoor" in warn_str) else "High"
            findings.append(_Finding(
                severity=sev,
                cvss=0.0,
                category="Version",
                title=warn_str[:100],
                context=f"Port {p['port']} — {p['service']} {p['version']}",
                action=f"Update {p['service']} to the latest stable release immediately.",
            ))

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    for ssl_res in full_result.get("ssl_results", []):
        for f in ssl_res.findings:
            if f.severity == "Info":
                continue
            findings.append(_Finding(
                severity=f.severity,
                cvss=0.0,
                category="SSL/TLS",
                title=f.title,
                context=f"Port {ssl_res.port}/tcp ({ssl_res.target})",
                action=f.detail[:150],
            ))

    # ── HTTP Security Headers ─────────────────────────────────────────────────
    for http_res in full_result.get("http_results", []):
        for hf in http_res.missing_headers:
            findings.append(_Finding(
                severity=hf.severity,
                cvss=0.0,
                category="HTTP Header",
                title=f"Missing security header: {hf.name}",
                context=http_res.url,
                action=hf.recommendation,
            ))
        for header_name, value in http_res.info_disclosure:
            findings.append(_Finding(
                severity="Low",
                cvss=0.0,
                category="Info Disclosure",
                title=f"Server info exposed: {header_name}: {value[:50]}",
                context=http_res.url,
                action=f"Remove or obscure the '{header_name}' response header to reduce fingerprinting.",
            ))

    # ── Gobuster high-interest paths ──────────────────────────────────────────
    gobuster = full_result.get("gobuster_result")
    if gobuster and getattr(gobuster, "interesting_paths", None):
        for f in gobuster.interesting_paths:
            if _path_severity(f.path):
                findings.append(_Finding(
                    severity="High",
                    cvss=0.0,
                    category="Directory",
                    title=f"Sensitive path accessible: {f.path}",
                    context=gobuster.target,
                    action=f"Restrict access to '{f.path}' — may expose admin interface, "
                           "credentials, config files, or source control data.",
                ))

    findings.sort(key=lambda x: (_SEVERITY_ORDER.get(x.severity, 0), x.cvss), reverse=True)
    return findings


def _overall_risk_from_findings(findings: list[_Finding]) -> tuple[str, str]:
    if not findings:
        return "🟢 LOW", "No significant findings detected"
    top = findings[0].severity
    count = sum(1 for f in findings if f.severity == top)
    labels = {
        "Critical": ("🔴 CRITICAL", f"{count} critical finding(s) require immediate action"),
        "High":     ("🟠 HIGH",     f"{count} high-severity finding(s) detected"),
        "Medium":   ("🟡 MEDIUM",   f"{count} medium-severity finding(s) detected"),
        "Low":      ("🔵 LOW",      f"{count} low-severity finding(s) — monitor and plan remediation"),
    }
    return labels.get(top, ("🟢 LOW", "No significant findings"))


def _full_scan_executive_summary(full_result: dict, findings: list[_Finding]) -> list[str]:
    target       = full_result.get("target", "unknown")
    nmap_result  = full_result.get("nmap_result", {})
    ports        = _parse_ports(nmap_result.get("output", ""))
    open_ports   = [p for p in ports if p["state"] == "open"]
    cve_results  = full_result.get("cve_results", [])
    ssl_results  = full_result.get("ssl_results", [])
    http_results = full_result.get("http_results", [])

    total_cves  = sum(len(r.cves) for r in cve_results)
    crit_cves   = sum(1 for r in cve_results for c in r.cves if c.cvss_severity == "Critical")
    high_cves   = sum(1 for r in cve_results for c in r.cves if c.cvss_severity == "High")
    ssl_issues  = sum(1 for r in ssl_results for f in r.findings if f.severity not in ("Info",))
    miss_hdrs   = sum(1 for r in http_results for f in r.missing_headers)

    risk_label, risk_reason = _overall_risk_from_findings(findings)

    lines = [
        "## Executive Summary",
        "",
        f"A comprehensive security assessment was performed against **`{target}`**. "
        f"{len(open_ports)} open port(s) were identified, hosting {len(cve_results)} versioned service(s).",
        "",
    ]

    if findings:
        crit_count = sum(1 for f in findings if f.severity == "Critical")
        high_count = sum(1 for f in findings if f.severity == "High")
        med_count  = sum(1 for f in findings if f.severity == "Medium")

        lines.append(
            f"**{len(findings)} security findings** were identified in total: "
            f"{crit_count} Critical, {high_count} High, {med_count} Medium."
        )
        lines.append("")

        if crit_cves or high_cves:
            lines.append(
                f"The CVE analysis found **{total_cves} vulnerabilities** across the detected services, "
                f"including {crit_cves} Critical and {high_cves} High severity entries. "
                "Affected services should be patched or updated as a priority."
            )
            lines.append("")

        if ssl_issues:
            lines.append(
                f"**{ssl_issues} SSL/TLS issue(s)** were found. Weak TLS configurations expose "
                "encrypted traffic to interception and downgrade attacks."
            )
            lines.append("")

        if miss_hdrs:
            lines.append(
                f"**{miss_hdrs} HTTP security header(s)** are missing. "
                "Security headers are a low-effort, high-impact defense against XSS, "
                "clickjacking, and MIME-type attacks."
            )
            lines.append("")
    else:
        lines += [
            "No significant security findings were detected during this assessment. "
            "The target appears to be well-hardened. Continue regular scanning to monitor for changes.",
            "",
        ]

    lines += [
        f"**Overall Risk Level: {risk_label}**  —  {risk_reason}.",
        "",
    ]
    return lines


def _priority_fix_list(findings: list[_Finding]) -> list[str]:
    if not findings:
        return []

    lines = ["## Priority Fix List", ""]
    groups = {
        "Critical": ("🔴 Immediate Action Required",  "Fix within 24–48 hours"),
        "High":     ("🟠 Fix Within 7 Days",          "Address before next business week"),
        "Medium":   ("🟡 Fix Within 30 Days",         "Schedule in the next sprint/cycle"),
        "Low":      ("🔵 Recommendations",            "Apply when resources allow"),
    }

    for sev, (label, subtitle) in groups.items():
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines += [f"### {label}", f"_{subtitle}_", ""]
        lines += ["| # | Category | Finding | Context | Action |",
                  "|---|---|---|---|---|"]
        for i, f in enumerate(group, 1):
            title_safe = f.title.replace("|", "\\|")
            ctx_safe   = f.context.replace("|", "\\|")
            action_safe = f.action[:90].replace("|", "\\|") + ("…" if len(f.action) > 90 else "")
            lines.append(f"| {i} | {f.category} | {title_safe} | {ctx_safe} | {action_safe} |")
        lines.append("")

    return lines


def generate_full_scan_report(full_result: dict) -> str:
    """
    Generate a comprehensive Markdown security report from a Full Scan result dict.

    Expected keys in full_result:
        target, nmap_result, cve_results, ssl_results, http_results, gobuster_result

    Returns the file path of the saved .md report.
    """
    _ensure_dir()
    ts     = _timestamp()
    target = full_result.get("target", "unknown")
    safe   = target.replace(".", "_").replace(":", "_")
    filename = f"{REPORT_DIR}/fullscan_{safe}_{ts}.pdf"

    nmap_result  = full_result.get("nmap_result", {})
    cve_results  = full_result.get("cve_results", [])
    ssl_results  = full_result.get("ssl_results", [])
    http_results = full_result.get("http_results", [])
    gobuster     = full_result.get("gobuster_result")

    findings   = _collect_findings(full_result)
    risk_label, risk_reason = _overall_risk_from_findings(findings)

    raw_out  = nmap_result.get("output", "")
    ports    = _parse_ports(raw_out)
    host_info = _parse_host_info(raw_out)

    # ── Report header ─────────────────────────────────────────────────────────
    lines = [
        f"# FENRIR Security Report — `{target}`",
        "",
        "| | |",
        "|---|---|",
        f"| **Target**        | `{target}` |",
        f"| **Scan Date**      | {ts} |",
        f"| **Overall Risk**   | {risk_label} |",
        f"| **Total Findings** | {len(findings)} |",
        f"| **Open Ports**     | {sum(1 for p in ports if p['state'] == 'open')} |",
        f"| **CVEs Found**     | {sum(len(r.cves) for r in cve_results)} |",
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += _full_scan_executive_summary(full_result, findings)

    # ── Priority Fix List ─────────────────────────────────────────────────────
    lines += _priority_fix_list(findings)

    # ── Detailed Findings: Nmap ───────────────────────────────────────────────
    lines += ["---", "", "## Detailed Findings", "", "### Port Scan (Nmap)", ""]
    if host_info:
        lines += ["| Field | Value |", "|---|---|"]
        for k, v in host_info.items():
            lines.append(f"| **{k}** | {v} |")
        lines.append("")

    if ports:
        lines += [
            "| Port | State | Service | Version | Risk | Note |",
            "|---|---|---|---|---|---|",
        ]
        for p in ports:
            state_icon      = "🟢" if p["state"] == "open" else "🟡"
            sev_icon, note  = _port_severity(p["port"])
            ver_warn        = _check_vulnerable_version(p["service"], p["version"])
            note_col        = ver_warn or note or "—"
            lines.append(
                f"| `{p['port']}` | {state_icon} {p['state']} "
                f"| {p['service']} | {p['version'] or '—'} "
                f"| {sev_icon or '—'} | {note_col} |"
            )
        lines.append("")

    # ── Detailed Findings: CVE ────────────────────────────────────────────────
    if cve_results:
        lines += ["### CVE Analysis", ""]
        for svc in cve_results:
            if not svc.cves:
                continue
            top_sev  = _top_severity(svc.cves)
            sev_icon = _severity_icon(top_sev)
            lines += [
                f"#### {sev_icon} Port {svc.port}/{svc.protocol} — {svc.product} {svc.version}",
                "",
                "| CVE ID | CVSS | Severity | Published | Description |",
                "|---|---|---|---|---|",
            ]
            for cve in svc.cves:
                desc = (cve.description[:100] + "…") if len(cve.description) > 100 else cve.description
                lines.append(
                    f"| [`{cve.cve_id}`]({cve.url}) | {cve.cvss_score} "
                    f"| {cve.cvss_severity} | {cve.published} | {desc} |"
                )
            lines.append("")

    # ── Detailed Findings: SSL/TLS ────────────────────────────────────────────
    if ssl_results:
        lines += ["### SSL/TLS Analysis", ""]
        for r in ssl_results:
            if not r.reachable:
                lines += [f"**Port {r.port}/tcp** — Could not connect: {r.error}", ""]
                continue
            non_info = [f for f in r.findings if f.severity != "Info"]
            lines += [
                f"**Port {r.port}/tcp** — {r.negotiated_version}  "
                f"Cipher: `{r.cipher_name}`",
                f"Certificate: {r.cert_subject} (issued by {r.cert_issuer})",
                f"Expiry: {r.cert_expiry} ({r.days_until_expiry} days remaining)",
                "",
            ]
            if non_info:
                lines += ["| Severity | Finding | Detail |", "|---|---|---|"]
                for f in non_info:
                    lines.append(f"| {f.severity} | {f.title} | {f.detail[:120]} |")
                lines.append("")

    # ── Detailed Findings: HTTP Headers ──────────────────────────────────────
    if http_results:
        lines += ["### HTTP Security Headers", ""]
        for r in http_results:
            if r.error:
                lines += [f"**{r.url}** — Error: {r.error}", ""]
                continue
            lines += [
                f"**{r.url}** (HTTP {r.status_code})",
                "",
                "| Header | Present | Severity | Value / Recommendation |",
                "|---|---|---|---|",
            ]
            for f in r.findings:
                status = "✅ Yes" if f.present else "❌ No"
                val    = f.value[:60] if f.present else f.recommendation[:70]
                lines.append(f"| `{f.name}` | {status} | {f.severity if not f.present else '—'} | {val} |")
            if r.info_disclosure:
                lines.append("")
                lines.append("**Information Disclosure Headers:**")
                for h, v in r.info_disclosure:
                    lines.append(f"- `{h}: {v}` — remove or obscure this header")
            lines.append("")

    # ── Detailed Findings: Gobuster ───────────────────────────────────────────
    if gobuster and getattr(gobuster, "findings", None):
        lines += ["### Directory Discovery (Gobuster)", ""]
        total = len(gobuster.findings)
        interesting = getattr(gobuster, "interesting_paths", [])
        lines.append(f"{total} path(s) found. {len(interesting)} accessible/redirected.")
        lines.append("")
        if interesting:
            lines += ["| Path | Status | Size | Note |", "|---|---|---|---|"]
            for f in interesting:
                sev  = _path_severity(f.path)
                note = (f"← {sev}" if sev else "") + ("  " + _size_note(f.size) if _size_note(f.size) else "")
                lines.append(f"| `{f.path}` | {f.status} | {f.size}B | {note or '—'} |")
            lines.append("")

    # ── Raw Nmap output ───────────────────────────────────────────────────────
    if raw_out.strip():
        lines += [
            "---",
            "",
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

    _md_to_pdf("\n".join(lines), filename)
    return filename