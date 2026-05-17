"""
ui/terminal.py
Rich-powered terminal UI for FENRIR.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.columns import Columns
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box
import time

console = Console()


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner():
    console.clear()
    banner = Text()
    banner.append("  ███████╗███████╗███╗   ██╗██████╗ ██╗██████╗ \n",  style="bold red")
    banner.append("  ██╔════╝██╔════╝████╗  ██║██╔══██╗██║██╔══██╗\n", style="bold red")
    banner.append("  █████╗  █████╗  ██╔██╗ ██║██████╔╝██║██████╔╝\n", style="bold red")
    banner.append("  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══██╗██║██╔══██╗\n", style="bold red")
    banner.append("  ██║     ███████╗██║ ╚████║██║  ██║██║██║  ██║\n",  style="bold red")
    banner.append("  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝\n", style="bold red")
    banner.append("  Flexible Engine for Network Reconnaissance", style="dim")
    banner.append(" & Intelligent Red-teaming\n", style="dim")
    banner.append("  v1.1.0", style="bold white")

    console.print(Panel(
        banner,
        title="[bold red]FENRIR[/bold red]",
        subtitle="[dim]Powered by Claude · nmap · NVD[/dim]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()


# ── Main menu ─────────────────────────────────────────────────────────────────

MENU_OPTIONS = [
    ("1", "fullscan",   "Full Scan",       "Complete assessment: Nmap + CVE + SSL + HTTP Headers + Dirs"),
    ("2", "nmap",       "Nmap Scan",       "Scan a target for open ports, services and CVEs"),
    ("3", "gobuster",   "Dir Bruteforce",  "Find hidden paths on a web server"),
    ("4", "subdomain",  "Subdomain Enum",  "Enumerate subdomains via subfinder / amass / crt.sh"),
    ("5", "takeover",   "Takeover Check",  "Check subdomains for dangling CNAME takeover vulnerabilities"),
    ("6", "cors",       "CORS Scanner",    "Detect CORS misconfigurations (origin reflection, null, wildcard)"),
    ("7", "redirect",   "Open Redirect",   "Test URL parameters for open redirect vulnerabilities"),
    ("8", "xss",       "XSS Scanner",     "Inject XSS payloads into URL parameters and detect reflection"),
    ("9", "sqli",      "SQLi Tester",     "Test URL parameters for SQL injection (error + boolean based)"),
    ("r", "redteam",   "AI Red-Team",     "Fire adversarial prompts against an AI endpoint"),
    ("0", "quit",      "Exit",            "Quit the program"),
]


def print_main_menu():
    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2),
        show_edge=False,
    )
    table.add_column("key",  style="bold red",   width=4)
    table.add_column("mode", style="bold white",  width=14)
    table.add_column("desc", style="dim",         width=50)

    for key, _, label, desc in MENU_OPTIONS:
        table.add_row(Text(f"[{key}]", style="bold red"), label, desc)

    console.print(Panel(table, title="[bold]Main Menu[/bold]", border_style="dim red"))
    console.print()


def prompt_main_menu() -> str:
    """Show menu and return the selected mode string."""
    valid = {opt[0]: opt[1] for opt in MENU_OPTIONS}
    while True:
        choice = Prompt.ask(
            "[bold red]>[/bold red] Select",
            choices=list(valid.keys()),
            show_choices=True,
        )
        return valid[choice]


# ── Target input ──────────────────────────────────────────────────────────────

def prompt_scan_type() -> str:
    """Show nmap scan-type menu and return the chosen key ('1'–'4')."""
    from tools.nmap_tool import SCAN_TYPES

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2), show_edge=False)
    table.add_column("key",   style="bold red",  width=4)
    table.add_column("name",  style="bold white", width=18)
    table.add_column("desc",  style="dim",        width=46)

    for key, (name, desc, _, _) in SCAN_TYPES.items():
        table.add_row(f"[{key}]", name, desc)

    console.print(Panel(table, title="[bold]Scan Type[/bold]", border_style="dim red"))
    return Prompt.ask(
        "[bold red]>[/bold red] Scan-Typ wählen",
        choices=list(SCAN_TYPES.keys()),
        default="2",
        show_choices=True,
    )


def prompt_target(label: str = "Target IP / hostname") -> str:
    return Prompt.ask(f"[bold red]>[/bold red] {label}").strip()


def confirm_scan_target(target: str) -> bool:
    """Ask the user to confirm authorization for an unknown target. Returns True if confirmed."""
    return Confirm.ask(
        f"[yellow]⚠ Target '[bold]{target}[/bold]' ist nicht in der Allowlist.\n"
        "  Bist du autorisiert, dieses Ziel zu scannen?[/yellow]",
        default=False,
    )


def prompt_redteam_target() -> tuple[str, str, str]:
    """Returns (target_name, mode, http_url)."""
    name = Prompt.ask("[bold red]>[/bold red] Target AI name (e.g. my-chatbot)").strip()
    use_http = Confirm.ask("Does the target expose an HTTP endpoint?", default=False)
    if use_http:
        url = Prompt.ask("[bold red]>[/bold red] HTTP URL").strip()
        return name, "http", url
    return name, "anthropic", ""


# ── Spinner / progress helpers ────────────────────────────────────────────────

def spinner(label: str):
    """
    Context manager — shows a spinner while a block runs.

    Usage:
        with spinner("Running nmap …"):
            result = run_nmap(target)
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bold red"),
        TextColumn("[bold]{task.description}[/bold]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


class ScanProgress:
    """
    Multi-step progress bar for sequential operations
    (e.g. red-team: N attacks).

    Usage:
        with ScanProgress(total=10, label="Attacks") as p:
            for attack in attacks:
                p.advance(attack_name)
    """
    def __init__(self, total: int, label: str = "Progress"):
        self._total = total
        self._label = label
        self._progress = Progress(
            SpinnerColumn(spinner_name="dots2", style="bold red"),
            TextColumn("[bold]{task.description}[/bold]"),
            BarColumn(bar_width=30, style="red", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )
        self._task = None

    def __enter__(self):
        self._progress.start()
        self._task = self._progress.add_task(self._label, total=self._total)
        return self

    def advance(self, description: str = ""):
        self._progress.update(self._task, advance=1, description=description)

    def __exit__(self, *_):
        self._progress.stop()


# ── Result display ────────────────────────────────────────────────────────────

def print_nmap_result(nmap_result: dict):
    target = nmap_result.get("target", "?")
    output = nmap_result.get("output", "").strip()
    success_flag = nmap_result.get("success", False)

    status_text = "[bold green]SUCCESS[/bold green]" if success_flag else "[bold red]FAILED[/bold red]"
    console.print()
    console.print(Rule(f"[bold]Nmap Scan — {target}[/bold]", style="red"))
    console.print(f"  Status: {status_text}")
    console.print()

    if output:
        console.print(Panel(
            Syntax(output, "text", theme="monokai", word_wrap=True),
            title="[dim]Raw Output[/dim]",
            border_style="dim",
        ))

    if nmap_result.get("error"):
        console.print(Panel(
            Text(nmap_result["error"], style="red"),
            title="[bold red]Errors[/bold red]",
            border_style="red",
        ))


def print_cve_results(cve_results: list):
    """Display CVE lookup results as a rich table per service."""
    if not cve_results:
        console.print("[dim]  No versioned services found — CVE lookup skipped.[/dim]")
        return

    console.print()
    console.print(Rule("[bold]CVE Lookup Results[/bold]", style="red"))

    for svc in cve_results:
        label = f"{svc.product} {svc.version}".strip() or svc.service
        icon  = "🔴" if svc.critical_cves else ("🟠" if svc.high_cves else "🟡")
        title = f"{icon}  Port [bold]{svc.port}/{svc.protocol}[/bold] — {label}"

        if not svc.cves:
            console.print(Panel("[dim]No CVEs found.[/dim]", title=title, border_style="dim"))
            continue

        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        table.add_column("CVE ID",      style="cyan bold",  width=18)
        table.add_column("CVSS",        style="white",       width=6,  justify="right")
        table.add_column("Severity",    width=10)
        table.add_column("Published",   style="dim",         width=12)
        table.add_column("Description", style="dim",         ratio=1)

        for cve in svc.cves:
            sev_color = {
                "Critical": "bold red",
                "High":     "bold yellow",
                "Medium":   "yellow",
                "Low":      "green",
            }.get(cve.cvss_severity, "white")

            table.add_row(
                cve.cve_id,
                f"{cve.cvss_score:.1f}",
                Text(cve.cvss_severity, style=sev_color),
                cve.published,
                cve.description[:80] + ("…" if len(cve.description) > 80 else ""),
            )

        border = "red" if svc.critical_cves else ("yellow" if svc.high_cves else "dim")
        console.print(Panel(table, title=title, border_style=border))


def print_redteam_results(report):
    """Display red-team attack results with CVSS scores."""
    console.print()
    console.print(Rule("[bold]Red-Team Results[/bold]", style="red"))

    # Summary header
    rate = report.success_rate
    rate_color = "red" if rate >= 0.5 else ("yellow" if rate >= 0.2 else "green")

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), show_edge=False)
    summary.add_column("k", style="dim", width=20)
    summary.add_column("v", style="bold white")
    summary.add_row("Target AI",    report.target_name)
    summary.add_row("Total Attacks", str(len(report.results)))
    summary.add_row("Bypassed",     f"[{rate_color}]{len(report.successful_attacks)}[/{rate_color}]")
    summary.add_row("Bypass Rate",  f"[{rate_color}]{rate:.0%}[/{rate_color}]")
    console.print(Panel(summary, title="[bold]Summary[/bold]", border_style="dim red"))
    console.print()

    # Per-attack table
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("Result",    width=4,  justify="center")
    table.add_column("Attack",    style="white bold", ratio=2)
    table.add_column("Category", style="dim",          width=12)
    table.add_column("CVSS",     width=6,  justify="right")
    table.add_column("Severity", width=10)

    for r in report.results:
        from ai_red_team.cvss_scorer import score_attack
        cvss = score_attack(r.category, r.success)

        icon = "🔴" if r.success else "🟢"
        sev_color = {
            "Critical": "bold red",
            "High":     "bold yellow",
            "Medium":   "yellow",
            "Low":      "green",
        }.get(cvss.severity if cvss else "", "dim")

        table.add_row(
            icon,
            r.attack_name,
            r.category,
            f"{cvss.score:.1f}" if cvss else "—",
            Text(cvss.severity if cvss else "—", style=sev_color),
        )

    console.print(table)


def confirm_gobuster() -> bool:
    """Ask whether to include a Gobuster directory scan in the full scan."""
    return Confirm.ask(
        "  [dim]Include directory scan (Gobuster)?[/dim] [dim](slower, but finds hidden paths)[/dim]",
        default=False,
    )


def print_scan_step(step: int, total: int, label: str):
    """Print a numbered step header during Full Scan."""
    console.print()
    console.print(f"  [bold red][{step}/{total}][/bold red]  [bold white]{label}[/bold white]")


def print_ssl_results(ssl_results: list):
    """Display SSL/TLS analysis results."""
    if not ssl_results:
        return
    console.print()
    console.print(Rule("[bold]SSL/TLS Analysis[/bold]", style="red"))

    for r in ssl_results:
        non_info = [f for f in r.findings if f.severity != "Info"]
        border = "red" if r.has_critical else ("yellow" if r.has_high else "dim")
        icon   = "🔴" if r.has_critical else ("🟠" if r.has_high else "🟢")
        title  = f"{icon}  Port [bold]{r.port}/tcp[/bold] — {r.negotiated_version or 'TLS'}"

        if not r.reachable:
            console.print(Panel(f"[dim]Could not connect: {r.error}[/dim]", title=title, border_style="dim"))
            continue

        if not non_info:
            console.print(Panel("[dim]No SSL/TLS issues found.[/dim]", title=title, border_style="dim"))
            continue

        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        table.add_column("Sev",     width=10)
        table.add_column("Finding", style="bold white", ratio=1)
        table.add_column("Detail",  style="dim",        ratio=2)

        for f in non_info:
            sev_color = {"Critical": "bold red", "High": "bold yellow",
                         "Medium": "yellow", "Low": "green"}.get(f.severity, "white")
            table.add_row(
                Text(f.severity, style=sev_color),
                f.title,
                f.detail[:100] + ("…" if len(f.detail) > 100 else ""),
            )

        meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), show_edge=False)
        meta.add_column("k", style="dim", width=20)
        meta.add_column("v", style="white")
        if r.cert_subject:
            meta.add_row("Subject", r.cert_subject)
        if r.cert_issuer:
            meta.add_row("Issuer",  r.cert_issuer)
        if r.cert_expiry:
            days_str = f"{r.days_until_expiry}d remaining" if not r.cert_expired else "EXPIRED"
            meta.add_row("Expiry",  f"{r.cert_expiry}  ({days_str})")
        tls_support = "  ".join(
            v for v, enabled in [("TLS1.0", r.tls10_enabled), ("TLS1.1", r.tls11_enabled),
                                  ("TLS1.2", r.tls12_enabled), ("TLS1.3", r.tls13_enabled)]
            if enabled
        )
        if tls_support:
            meta.add_row("Supported", tls_support)

        from rich.columns import Columns
        console.print(Panel(Columns([meta, table]), title=title, border_style=border))


def print_http_header_results(http_results: list):
    """Display HTTP security header check results."""
    if not http_results:
        return
    console.print()
    console.print(Rule("[bold]HTTP Security Headers[/bold]", style="red"))

    for r in http_results:
        if r.error:
            console.print(Panel(f"[dim]Error: {r.error}[/dim]", title=f"  {r.url}", border_style="dim"))
            continue

        missing = r.missing_headers
        border = "yellow" if r.has_high_issues else "dim"
        icon   = "🟠" if r.has_high_issues else "🟡" if missing else "🟢"
        title  = f"{icon}  {r.url}  [dim](HTTP {r.status_code})[/dim]"

        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        table.add_column("",        width=3,  justify="center")
        table.add_column("Header",  style="white", ratio=1)
        table.add_column("Sev",     width=8)
        table.add_column("Status / Value", style="dim", ratio=2)

        for f in r.findings:
            if f.present:
                val = f.value[:60] + ("…" if len(f.value) > 60 else "")
                table.add_row("✅", f.name, "", val)
            else:
                sev_color = {"High": "bold yellow", "Medium": "yellow", "Low": "dim"}.get(f.severity, "dim")
                table.add_row("❌", f.name, Text(f.severity, style=sev_color), f.recommendation[:60])

        lines = [table]
        if r.info_disclosure:
            disc = "  ".join(f"[bold]{h}[/bold]: {v[:30]}" for h, v in r.info_disclosure)
            lines.append(Text(f"\n  Info disclosure: {disc}", style="dim yellow"))

        from rich.console import Group
        console.print(Panel(Group(*lines), title=title, border_style=border))


def print_cors_results(result):
    """Display CORS scan results."""
    console.print()
    console.print(Rule(f"[bold]CORS Scanner — {result.target}[/bold]", style="red"))

    if not result.findings:
        if result.error:
            console.print(f"  [red]Error: {result.error}[/red]")
        else:
            console.print("  [dim green]No CORS misconfigurations detected.[/dim green]")
        return

    sev_color = {
        "Critical": "bold red",
        "High":     "bold yellow",
        "Medium":   "yellow",
        "Low":      "dim",
    }
    sev_icon = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🔵",
    }

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("Sev",         width=12)
    table.add_column("Origin Sent", style="cyan",       ratio=2)
    table.add_column("ACAO",        style="dim",         ratio=2)
    table.add_column("ACAC",        width=8,  justify="center")
    table.add_column("Detail",      style="dim",         ratio=3)

    for f in result.findings:
        icon  = sev_icon.get(f.severity, "")
        style = sev_color.get(f.severity, "white")
        acac_display = Text("true", style="bold red") if f.acac_header == "true" else Text(f.acac_header, style="dim")
        table.add_row(
            Text(f"{icon} {f.severity}", style=style),
            f.origin_sent,
            f.acao_header[:40],
            acac_display,
            f.detail[:70] + ("…" if len(f.detail) > 70 else ""),
        )

    border = "red" if result.has_critical else ("yellow" if result.has_high else "dim yellow")
    console.print(Panel(table, title="[bold]CORS Findings[/bold]", border_style=border))


def print_takeover_results(result):
    """Display subdomain takeover check results."""
    console.print()
    console.print(Rule(f"[bold]Subdomain Takeover Check — {result.target}[/bold]", style="red"))
    console.print(
        f"  Checked: [bold white]{result.checked}[/bold white] subdomain(s)  |  "
        f"Vulnerable: [bold {'red' if result.has_findings else 'green'}]{len(result.vulnerable)}[/bold {'red' if result.has_findings else 'green'}]"
    )

    if not result.vulnerable:
        console.print("  [dim green]No takeover vulnerabilities detected.[/dim green]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("Conf",      width=8)
    table.add_column("Subdomain", style="bold cyan",   ratio=2)
    table.add_column("CNAME",     style="dim",          ratio=2)
    table.add_column("Service",   style="bold white",   width=18)
    table.add_column("Indicator", style="dim",          ratio=2)

    for f in result.vulnerable:
        conf_style = "bold red" if f.confidence == "High" else "bold yellow"
        icon = "🔴" if f.confidence == "High" else "🟠"
        table.add_row(
            Text(f"{icon} {f.confidence}", style=conf_style),
            f.subdomain,
            f.cname,
            f.service,
            f.indicator[:50] + ("…" if len(f.indicator) > 50 else ""),
        )

    border = "red" if result.high_confidence else "yellow"
    console.print(Panel(table, title="[bold red]Vulnerable Subdomains[/bold red]", border_style=border))


def print_subdomain_results(result):
    """Display subdomain enumeration results."""
    console.print()
    console.print(Rule(f"[bold]Subdomain Enumeration — {result.target}[/bold]", style="red"))
    console.print(f"  Source: [dim]{result.source}[/dim]   "
                  f"Found: [bold white]{result.count}[/bold white] subdomain(s)")

    if not result.subdomains:
        console.print("  [dim]No subdomains discovered.[/dim]")
        return

    # High-interest subdomains panel
    if result.interesting:
        hi_table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        hi_table.add_column("High-Interest Subdomain", style="bold yellow", ratio=1)
        for sub in result.interesting:
            hi_table.add_row(sub)
        console.print(Panel(hi_table,
                            title="[bold yellow]High-Interest Subdomains[/bold yellow]",
                            border_style="yellow"))

    # Full list
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("#",          style="dim",        width=5,  justify="right")
    table.add_column("Subdomain",  style="cyan",       ratio=1)

    for i, sub in enumerate(result.subdomains, 1):
        style = "bold yellow" if sub in result.interesting else ""
        table.add_row(str(i), Text(sub, style=style))

    console.print(Panel(table,
                        title=f"[bold]All Subdomains ({result.count})[/bold]",
                        border_style="dim red"))


def print_sqli_results(result):
    """Display SQL injection scan results."""
    console.print()
    console.print(Rule(f"[bold]SQL Injection Tester — {result.target}[/bold]", style="red"))

    if not result.findings:
        if result.error:
            console.print(f"  [red]Error: {result.error}[/red]")
        else:
            console.print("  [dim green]No SQL injection indicators detected.[/dim green]")
        return

    high = result.high_confidence
    console.print(
        f"  High-confidence: [bold red]{len(high)}[/bold red]  |  "
        f"Total findings: [bold white]{len(result.findings)}[/bold white]"
    )

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("Conf",      width=12)
    table.add_column("Parameter", style="cyan bold", width=14)
    table.add_column("DB Hint",   style="dim",        width=14)
    table.add_column("Detail",    style="dim",         ratio=3)

    conf_style = {"High": "bold red", "Medium": "bold yellow"}
    conf_icon  = {"High": "🔴", "Medium": "🟡"}

    for f in result.findings:
        style = conf_style.get(f.confidence, "white")
        icon  = conf_icon.get(f.confidence, "")
        detail_trunc = f.detail[:80] + ("…" if len(f.detail) > 80 else "")
        table.add_row(
            Text(f"{icon} {f.confidence}", style=style),
            f.parameter,
            f.db_type_hint,
            detail_trunc,
        )

    border = "red" if high else "yellow"
    console.print(Panel(
        table,
        title=f"[bold red]SQLi Findings ({len(result.findings)})[/bold red]",
        border_style=border,
    ))


def print_xss_results(result):
    """Display XSS scan results."""
    console.print()
    console.print(Rule(f"[bold]XSS Scanner — {result.target}[/bold]", style="red"))

    if not result.findings:
        if result.error:
            console.print(f"  [red]Error: {result.error}[/red]")
        else:
            console.print("  [dim green]No reflected XSS detected.[/dim green]")
        return

    confirmed = result.confirmed
    console.print(
        f"  Reflected findings: [bold red]{len(confirmed)}[/bold red]  |  "
        f"Parameters tested: [dim]{len({f.parameter for f in result.findings})}[/dim]"
    )

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("",          width=3, justify="center")
    table.add_column("Parameter", style="cyan bold", width=14)
    table.add_column("Payload",   style="dim",        ratio=2)
    table.add_column("Snippet",   style="dim",        ratio=3)

    for f in confirmed:
        snippet = f.response_snippet.replace("\n", " ").strip()[:70]
        snippet += "…" if len(f.response_snippet) > 70 else ""
        table.add_row(
            "🔴",
            f.parameter,
            f.payload[:50] + ("…" if len(f.payload) > 50 else ""),
            snippet,
        )

    console.print(Panel(
        table,
        title=f"[bold red]Reflected XSS Findings ({len(confirmed)})[/bold red]",
        border_style="red",
    ))


def print_redirect_results(result):
    """Display open redirect scan results."""
    console.print()
    console.print(Rule(f"[bold]Open Redirect Scanner — {result.target}[/bold]", style="red"))

    if not result.findings:
        if result.error:
            console.print(f"  [red]Error: {result.error}[/red]")
        else:
            console.print("  [dim green]No open redirect vulnerabilities detected.[/dim green]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("",          width=3,  justify="center")
    table.add_column("Parameter", style="cyan bold",  width=18)
    table.add_column("Payload",   style="dim",         ratio=2)
    table.add_column("Status",    width=8,  justify="center")
    table.add_column("Location",  style="dim",         ratio=3)

    for f in result.findings:
        loc_trunc = f.location_header[:55] + ("…" if len(f.location_header) > 55 else "")
        table.add_row(
            "🔴",
            f.parameter,
            f.payload,
            Text(str(f.status_code), style="bold yellow"),
            loc_trunc,
        )

    console.print(Panel(
        table,
        title=f"[bold red]Open Redirect Findings ({len(result.findings)})[/bold red]",
        border_style="red",
    ))


def print_report_saved(path: str):
    console.print()
    console.print(Panel(
        f"[bold green]✓[/bold green]  Report saved:\n  [cyan]{path}[/cyan]",
        border_style="green",
        padding=(0, 2),
    ))


def print_error(msg: str):
    console.print(Panel(
        Text(msg, style="bold red"),
        title="[bold red]Error[/bold red]",
        border_style="red",
    ))


def print_success(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def print_info(msg: str):
    console.print(f"  [dim]·[/dim]  [dim]{msg}[/dim]")


