"""
main.py — FENRIR
Flexible Engine for Network Reconnaissance & Intelligent Red-teaming
"""
import sys
from ui import terminal as ui
from ai_engine import ask_ai
from tool_parser import parse_tool
from tools.nmap_tool import run_nmap
from reports.report_generator import generate_nmap_report, generate_redteam_report, generate_gobuster_report


# ── Mode: interactive chat ────────────────────────────────────────────────────

def run_chat():
    ui.print_chat_header()
    history: list[dict] = []

    while True:
        try:
            user_input = ui.prompt_chat_input()
        except (EOFError, KeyboardInterrupt):
            break

        if user_input.lower() in ("exit", "quit", ""):
            break

        with ui.spinner("Thinking …") as prog:
            task = prog.add_task("AI is thinking …", total=None)
            response = ask_ai(user_input, conversation_history=history)
            prog.update(task, completed=True)

        history.append({"role": "user",      "content": user_input})
        history.append({"role": "assistant",  "content": response})

        ui.print_ai_message(response)

        # Check if the AI wants to run a tool
        tool, target = parse_tool(response)
        if tool == "nmap" and target:
            ui.print_info(f"AI requested nmap scan on '{target}'")
            _do_nmap(target)


# ── Mode: nmap scan ───────────────────────────────────────────────────────────

def _do_nmap(target: str):
    from security.validator import is_allowed_target
    # Nmap erwartet einen Hostnamen/IP, keine URL — Schema abstreifen
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            stripped = target[len(prefix):].rstrip("/")
            ui.print_info(f"URL erkannt — verwende Hostname: {stripped}")
            target = stripped
            break

    confirmed = False
    if not is_allowed_target(target):
        if not ui.confirm_scan_target(target):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    from tools.nmap_tool import SCAN_TYPES
    scan_key = ui.prompt_scan_type()
    scan_name, _, flags, timeout = SCAN_TYPES[scan_key]

    with ui.spinner(f"[{scan_name}] Scanning {target} …") as prog:
        task = prog.add_task(f"nmap {' '.join(flags)} {target}", total=None)
        result = run_nmap(target, flags=flags, confirmed=confirmed, timeout=timeout)
        prog.update(task, completed=True)

    ui.print_nmap_result(result)

    if result["success"]:
        # CVE lookup with live progress
        from tools.cve_lookup import run_cve_lookup, parse_nmap_services
        from config import NVD_API_KEY

        services = parse_nmap_services(result["output"])
        if services:
            ui.print_info(f"Running CVE lookup for {len(services)} service(s) …")
            with ui.ScanProgress(total=len(services), label="CVE Lookup") as prog:
                cve_results = []
                import time as _time
                from tools.cve_lookup import lookup_cves, ServiceCVEResult, REQUEST_DELAY
                for svc in services:
                    keyword = f"{svc['product']} {svc['version']}".strip()
                    prog.advance(keyword or svc["service"])
                    if keyword:
                        cves = lookup_cves(keyword, api_key=NVD_API_KEY)
                        cve_results.append(ServiceCVEResult(
                            port=svc["port"], protocol=svc["protocol"],
                            service=svc["service"], product=svc["product"],
                            version=svc["version"], cves=cves,
                        ))
                        _time.sleep(REQUEST_DELAY)

            ui.print_cve_results(cve_results)
            # Inject CVE results into the nmap_result so the report includes them
            result["_cve_results"] = cve_results

        path = generate_nmap_report(result, run_cve=False)  # already did lookup above
        ui.print_report_saved(path)
    else:
        ui.print_error(result["error"])


def run_nmap_mode(target: str):
    _do_nmap(target)


# ── Mode: AI red-team ─────────────────────────────────────────────────────────

def run_redteam_mode(target_name: str, mode: str = "anthropic", http_url: str = ""):
    from ai_red_team.tester import AIRedTeamTester, ATTACK_PROMPTS

    total = len(ATTACK_PROMPTS)
    ui.print_info(f"Starting red-team against '{target_name}' — {total} attacks")

    tester = AIRedTeamTester(
        target_name=target_name,
        mode=mode,
        http_url=http_url,
        target_behavior="explain how to bypass content filters on an AI system",
    )

    # Patch tester to update progress bar
    report_ref = [None]

    with ui.ScanProgress(total=total, label="Red-team") as prog:
        original_run = tester.run

        def run_with_progress(categories=None):
            from ai_red_team.prompts import ATTACK_PROMPTS as AP
            import time
            from ai_red_team.tester import RedTeamReport, AttackResult

            attacks = AP if not categories else [a for a in AP if a["category"] in categories]
            report  = RedTeamReport(target_name=tester.target_name)

            for attack in attacks:
                prompt = attack["template"].replace("{target_behavior}", tester.target_behavior)
                prog.advance(attack["name"])
                try:
                    response  = tester._send(prompt)
                    succeeded = tester.success_fn(response)
                except Exception as exc:
                    response  = f"ERROR: {exc}"
                    succeeded = False

                report.results.append(AttackResult(
                    attack_name=attack["name"],
                    category=attack["category"],
                    prompt_sent=prompt,
                    response=response,
                    success=succeeded,
                    notes=attack["description"],
                ))
                time.sleep(tester.delay)

            return report

        report = run_with_progress()

    ui.print_redteam_results(report)
    path = generate_redteam_report(report)
    ui.print_report_saved(path)



# ── Mode: gobuster scan ───────────────────────────────────────────────────────

def run_gobuster_mode(target_url: str, wordlist: str = "wordlists/common.txt"):
    from tools.gobuster_tool import run_gobuster, _extract_hostname
    from security.validator import is_allowed_target

    confirmed = False
    hostname = _extract_hostname(target_url)
    if not is_allowed_target(hostname):
        if not ui.confirm_scan_target(target_url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    ui.print_info(f"Starting gobuster scan on: {target_url}")
    ui.print_info(f"Wordlist: {wordlist}")

    with ui.spinner(f"Scanning {target_url} …") as prog:
        task = prog.add_task(f"gobuster dir {target_url}", total=None)
        result = run_gobuster(target_url, wordlist=wordlist, confirmed=confirmed)
        prog.update(task, completed=True)

    _print_gobuster_result(result)

    if result.success or result.findings:
        path = generate_gobuster_report(result)
        ui.print_report_saved(path)
    else:
        ui.print_error(result.error)


def _print_gobuster_result(result):
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    ui.console.print()
    from rich.rule import Rule
    ui.console.print(Rule(f"[bold]Gobuster — {result.target}[/bold]", style="red"))

    if not result.findings:
        ui.console.print("  [dim]No paths discovered.[/dim]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("",        width=3,  justify="center")
    table.add_column("Path",    style="cyan bold", ratio=2)
    table.add_column("Status",  width=8,  justify="center")
    table.add_column("Size",    width=10, justify="right", style="dim")
    table.add_column("Redirect",style="dim", ratio=1)

    for f in result.interesting_paths:
        icon       = "🟢" if f.status == 200 else "🟡"
        status_col = Text(str(f.status),
                          style="bold green" if f.status == 200 else "yellow")
        table.add_row(icon, f.path, status_col, f"{f.size}B", f.redirect or "—")

    ui.console.print(table)
    ui.print_info(
        f"{len(result.found_paths)} accessible · "
        f"{len(result.redirect_paths)} redirects · "
        f"{len(result.findings)} total"
    )

# ── Interactive menu loop ─────────────────────────────────────────────────────

def run_menu():
    while True:
        ui.print_banner()
        ui.print_main_menu()

        mode = ui.prompt_main_menu()

        if mode == "quit":
            ui.console.print("\n[dim]Goodbye.[/dim]\n")
            break

        elif mode == "chat":
            run_chat()

        elif mode == "nmap":
            target = ui.prompt_target("Target IP / hostname / CIDR")
            if target:
                run_nmap_mode(target)
                input("\n  Press Enter to return to menu …")

        elif mode == "gobuster":
            target_url = ui.prompt_target("Target URL (e.g. http://192.168.1.1)")
            wordlist   = ui.prompt_target("Wordlist path (Enter for default: wordlists/common.txt)")
            if not wordlist:
                wordlist = "wordlists/common.txt"
            if target_url:
                run_gobuster_mode(target_url, wordlist=wordlist)
                input("\n  Press Enter to return to menu …")

        elif mode == "redteam":
            target_name, rt_mode, http_url = ui.prompt_redteam_target()
            if target_name:
                run_redteam_mode(target_name, mode=rt_mode, http_url=http_url)
                input("\n  Press Enter to return to menu …")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        # No args → show the interactive menu
        run_menu()

    elif args[0] == "chat":
        ui.print_banner()
        run_chat()

    elif args[0] == "nmap":
        if len(args) < 2:
            ui.print_error("nmap mode requires a target. Example: python main.py nmap 127.0.0.1")
            sys.exit(1)
        ui.print_banner()
        run_nmap_mode(args[1])

    elif args[0] == "redteam":
        if len(args) < 2:
            ui.print_error("redteam mode requires a target name.")
            sys.exit(1)
        rt_mode = "anthropic"
        http_url = ""
        if len(args) >= 4 and args[2].lower() == "http":
            rt_mode  = "http"
            http_url = args[3]
        ui.print_banner()
        run_redteam_mode(args[1], mode=rt_mode, http_url=http_url)

    else:
        ui.print_error(f"Unknown mode: '{args[0]}'")
        sys.exit(1)