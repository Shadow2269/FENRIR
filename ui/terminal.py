"""
ui/terminal.py
Rich-powered terminal UI for FENRIR.
FENRIR — Flexible Engine for Network Reconnaissance & Intelligent Red-teaming

Replaces plain print() / input() with:
  - Styled header banner
  - Interactive main menu with keyboard selection
  - Live progress spinners during scans
  - Colour-coded result panels
  - Formatted CVE and red-team result tables
  - Chat interface with message history display
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
from rich.markup import escape
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
    banner.append("  v1.0.1", style="bold white")

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
    ("1", "chat",      "AI Chat",        "Interactive red-team conversation with the AI agent"),
    ("2", "nmap",      "Nmap Scan",      "Scan a target for open ports and services"),
    ("3", "gobuster",  "Dir Bruteforce", "Find hidden paths on a web server"),
    ("4", "redteam",   "AI Red-Team",    "Fire adversarial prompts against an AI endpoint"),
    ("5", "quit",      "Exit",           "Quit the program"),
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
        table.add_row(f"[{key}]", label, desc)

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


def print_report_saved(path: str):
    console.print()
    console.print(Panel(
        f"[bold green]✓[/bold green]  Report saved:\n  [cyan]{path}[/cyan]\n  [dim]{path.replace('.md', '.html')}[/dim]",
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


# ── Chat UI ───────────────────────────────────────────────────────────────────

def print_chat_header():
    console.print(Panel(
        "[bold]FENRIR — AI Security Chat[/bold]\n[dim]Type [bold white]exit[/bold white] to return to menu[/dim]",
        border_style="dim red",
        padding=(0, 2),
    ))
    console.print()


def print_user_message(msg: str):
    console.print(Panel(
        escape(msg),
        title="[bold white]You[/bold white]",
        border_style="dim white",
        padding=(0, 2),
    ))


def print_ai_message(msg: str):
    console.print(Panel(
        escape(msg),
        title="[bold red]AI Agent[/bold red]",
        border_style="dim red",
        padding=(0, 2),
    ))
    console.print()


def prompt_chat_input() -> str:
    return Prompt.ask("[bold white]You[/bold white]").strip()