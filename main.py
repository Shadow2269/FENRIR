"""
main.py — FENRIR
Flexible Engine for Network Reconnaissance & Intelligent Red-teaming
"""
import sys
import re
from ui import terminal as ui
from tools.nmap_tool import run_nmap
from reports.report_generator import (
    generate_nmap_report, generate_redteam_report,
    generate_gobuster_report, generate_full_scan_report,
    generate_subdomain_report, generate_takeover_report,
    generate_cors_report, generate_redirect_report,
)


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
                from tools.cve_lookup import lookup_cves, ServiceCVEResult
                for svc in services:
                    keyword = f"{svc['product']} {svc['version']}".strip()
                    prog.advance(keyword or svc["service"])
                    if keyword:
                        cves = lookup_cves(
                            keyword,
                            product=svc["product"],
                            version=svc["version"],
                            api_key=NVD_API_KEY,
                        )
                        cve_results.append(ServiceCVEResult(
                            port=svc["port"], protocol=svc["protocol"],
                            service=svc["service"], product=svc["product"],
                            version=svc["version"], cves=cves,
                        ))

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

# ── Mode: Full Scan ───────────────────────────────────────────────────────────

def _strip_url_scheme(target: str) -> str:
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            stripped = target[len(prefix):].rstrip("/")
            ui.print_info(f"URL detected — using hostname: {stripped}")
            return stripped
    return target


def _detect_web_ports(nmap_output: str, target: str) -> list[tuple[int, bool]]:
    """Return (port, is_https) for HTTP/HTTPS services found in nmap output."""
    from tools.cve_lookup import parse_nmap_services
    services = parse_nmap_services(nmap_output)
    result = []
    seen = set()
    for svc in services:
        port    = svc["port"]
        service = svc["service"].lower()
        is_https = (
            service.startswith("ssl/") or
            "https" in service or
            port in (443, 8443, 4443)
        )
        is_http = (
            "http" in service or
            port in (80, 8080, 8000, 3000, 5000, 8888)
        )
        if (is_http or is_https) and port not in seen:
            seen.add(port)
            result.append((port, is_https))
    return result


def _detect_tls_ports(nmap_output: str) -> list[int]:
    """Return port numbers that carry TLS from nmap output."""
    from tools.cve_lookup import parse_nmap_services
    services = parse_nmap_services(nmap_output)
    tls_ports = []
    for svc in services:
        service = svc["service"].lower()
        port    = svc["port"]
        if service.startswith("ssl/") or "https" in service or port in (443, 8443, 4443, 465, 587, 993, 995):
            tls_ports.append(port)
    return tls_ports


def run_full_scan_mode(target: str, wordlist: str = "wordlists/common.txt"):
    from security.validator import is_allowed_target
    from tools.cve_lookup import parse_nmap_services, lookup_cves, ServiceCVEResult
    from tools.ssl_tool import check_ssl
    from tools.http_headers_tool import check_http_headers
    from config import NVD_API_KEY

    target = _strip_url_scheme(target)

    confirmed = False
    if not is_allowed_target(target):
        if not ui.confirm_scan_target(target):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    include_gobuster = ui.confirm_gobuster()
    total_steps = 5 if include_gobuster else 4

    full_result = {
        "target":          target,
        "nmap_result":     {},
        "cve_results":     [],
        "ssl_results":     [],
        "http_results":    [],
        "gobuster_result": None,
    }

    # ── Step 1: Nmap ──────────────────────────────────────────────────────────
    ui.print_scan_step(1, total_steps, f"Nmap Service Scan — {target}")
    with ui.spinner(f"Scanning {target} …") as prog:
        task = prog.add_task("nmap -sV ...", total=None)
        nmap_result = run_nmap(target, flags=["-sV"], confirmed=confirmed, timeout=180)
        prog.update(task, completed=True)

    full_result["nmap_result"] = nmap_result
    ui.print_nmap_result(nmap_result)

    if not nmap_result["success"]:
        ui.print_error(f"Nmap failed: {nmap_result['error']}")
        return

    services = parse_nmap_services(nmap_result["output"])
    ui.print_info(f"{len(services)} versioned service(s) found")

    # ── Step 2: CVE Lookup ────────────────────────────────────────────────────
    ui.print_scan_step(2, total_steps, f"CVE Lookup ({len(services)} service(s))")
    if services:
        with ui.ScanProgress(total=len(services), label="CVE Lookup") as prog:
            for svc in services:
                keyword = f"{svc['product']} {svc['version']}".strip()
                prog.advance(keyword or svc["service"])
                if keyword:
                    cves = lookup_cves(
                        keyword,
                        product=svc["product"],
                        version=svc["version"],
                        api_key=NVD_API_KEY,
                    )
                    full_result["cve_results"].append(ServiceCVEResult(
                        port=svc["port"], protocol=svc["protocol"],
                        service=svc["service"], product=svc["product"],
                        version=svc["version"], cves=cves,
                    ))
        total_cves = sum(len(r.cves) for r in full_result["cve_results"])
        ui.print_cve_results(full_result["cve_results"])
        ui.print_info(f"{total_cves} CVE(s) found")

    # ── Step 3: SSL/TLS ───────────────────────────────────────────────────────
    tls_ports = _detect_tls_ports(nmap_result["output"])
    ui.print_scan_step(3, total_steps, f"SSL/TLS Analysis ({len(tls_ports)} port(s))")
    for port in tls_ports:
        ui.print_info(f"  Checking {target}:{port} …")
        ssl_res = check_ssl(target, port)
        full_result["ssl_results"].append(ssl_res)
    ui.print_ssl_results(full_result["ssl_results"])

    # ── Step 4: HTTP Security Headers ─────────────────────────────────────────
    web_ports = _detect_web_ports(nmap_result["output"], target)
    ui.print_scan_step(4, total_steps, f"HTTP Security Headers ({len(web_ports)} URL(s))")
    for port, is_https in web_ports:
        ui.print_info(f"  Checking {'https' if is_https else 'http'}://{target}:{port} …")
        http_res = check_http_headers(target, port, use_tls=is_https)
        full_result["http_results"].append(http_res)
    ui.print_http_header_results(full_result["http_results"])

    # ── Step 5: Gobuster (optional) ───────────────────────────────────────────
    if include_gobuster and web_ports:
        first_port, first_https = web_ports[0]
        scheme = "https" if first_https else "http"
        gobuster_url = (
            f"{scheme}://{target}/"
            if (first_https and first_port == 443) or (not first_https and first_port == 80)
            else f"{scheme}://{target}:{first_port}/"
        )
        ui.print_scan_step(5, total_steps, f"Directory Scan — {gobuster_url}")
        from tools.gobuster_tool import run_gobuster
        with ui.spinner(f"Gobuster — {gobuster_url} …") as prog:
            task = prog.add_task("gobuster dir ...", total=None)
            gobuster_result = run_gobuster(gobuster_url, wordlist=wordlist, confirmed=confirmed)
            prog.update(task, completed=True)
        full_result["gobuster_result"] = gobuster_result
        _print_gobuster_result(gobuster_result)
    elif include_gobuster:
        ui.print_info("No HTTP/HTTPS ports found — skipping Gobuster.")

    # ── Generate report ───────────────────────────────────────────────────────
    ui.print_info("Generating report …")
    path = generate_full_scan_report(full_result)
    ui.print_report_saved(path)


# ── Mode: Subdomain Enumeration ──────────────────────────────────────────────

def run_subdomain_mode(domain: str):
    from tools.subdomain_tool import run_subdomain_enum
    from security.validator import is_allowed_target

    # Strip scheme if user pasted a URL
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):].rstrip("/").split("/")[0]
            ui.print_info(f"URL erkannt — verwende Domain: {domain}")
            break

    confirmed = False
    if not is_allowed_target(domain):
        if not ui.confirm_scan_target(domain):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    with ui.spinner(f"Enumerating subdomains for {domain} …") as prog:
        task = prog.add_task(f"subdomain enum {domain}", total=None)
        result = run_subdomain_enum(domain, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_subdomain_results(result)

    if result.success:
        path = generate_subdomain_report(result)
        ui.print_report_saved(path)
    else:
        ui.print_error(result.error)


# ── Mode: CORS Scanner ───────────────────────────────────────────────────────

def run_cors_mode(url: str):
    from tools.cors_scanner import scan_cors
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    # Ensure scheme present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    ui.print_info(f"Testing 7 crafted origins against: {url}")

    with ui.spinner(f"CORS scan {url} …") as prog:
        task = prog.add_task("cors scan", total=None)
        result = scan_cors(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_cors_results(result)
    path = generate_cors_report(result)
    ui.print_report_saved(path)


# ── Mode: Subdomain Takeover Check ───────────────────────────────────────────

def run_takeover_mode(domain: str):
    from tools.subdomain_tool import run_subdomain_enum
    from tools.takeover_checker import check_takeover
    from security.validator import is_allowed_target

    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):].rstrip("/").split("/")[0]

    confirmed = False
    if not is_allowed_target(domain):
        if not ui.confirm_scan_target(domain):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    # Step 1: enumerate subdomains
    ui.print_info(f"Step 1/2 — Enumerating subdomains for {domain} …")
    with ui.spinner(f"Subdomain enum {domain} …") as prog:
        task = prog.add_task("subdomain enum", total=None)
        sub_result = run_subdomain_enum(domain, confirmed=confirmed)
        prog.update(task, completed=True)

    if not sub_result.subdomains:
        ui.print_info("No subdomains found — nothing to check for takeover.")
        return

    ui.print_info(f"{sub_result.count} subdomain(s) found via {sub_result.source}")

    # Step 2: check each for takeover
    ui.print_info(f"Step 2/2 — Checking {sub_result.count} subdomain(s) for takeover …")
    with ui.ScanProgress(total=sub_result.count, label="Takeover Check") as prog:
        from tools.takeover_checker import (
            TakeoverResult, TakeoverFinding,
            _resolve_cname, _match_fingerprint, _confirm_via_http,
        )
        result = TakeoverResult(success=True, target=domain)
        for subdomain in sub_result.subdomains:
            prog.advance(subdomain)
            result.checked += 1
            cname = _resolve_cname(subdomain)
            if not cname:
                continue
            match = _match_fingerprint(cname)
            if not match:
                continue
            service, indicator, confidence = match
            if _confirm_via_http(subdomain, indicator):
                result.vulnerable.append(TakeoverFinding(
                    subdomain=subdomain,
                    cname=cname,
                    service=service,
                    indicator=indicator,
                    confidence=confidence,
                ))

    ui.print_takeover_results(result)
    path = generate_takeover_report(result)
    ui.print_report_saved(path)


# ── Mode: Open Redirect Scanner ──────────────────────────────────────────────

def run_redirect_mode(url: str):
    from tools.redirect_scanner import scan_redirect
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    total_params = 29   # _REDIRECT_PARAMS count
    total_payloads = 9  # _PAYLOADS count
    ui.print_info(f"Testing {total_params} redirect parameters × {total_payloads} payloads against: {url}")

    with ui.spinner(f"Open Redirect scan {url} …") as prog:
        task = prog.add_task("redirect scan", total=None)
        result = scan_redirect(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_redirect_results(result)
    path = generate_redirect_report(result)
    ui.print_report_saved(path)


# ── Interactive menu loop ─────────────────────────────────────────────────────

def run_menu():
    while True:
        ui.print_banner()
        ui.print_main_menu()

        mode = ui.prompt_main_menu()

        if mode == "quit":
            ui.console.print("\n[dim]Goodbye.[/dim]\n")
            break

        elif mode == "fullscan":
            target = ui.prompt_target("Target IP / hostname / domain")
            if target:
                run_full_scan_mode(target)
                input("\n  Press Enter to return to menu …")

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

        elif mode == "subdomain":
            domain = ui.prompt_target("Target domain (e.g. example.com)")
            if domain:
                run_subdomain_mode(domain)
                input("\n  Press Enter to return to menu …")

        elif mode == "takeover":
            domain = ui.prompt_target("Target domain (e.g. example.com)")
            if domain:
                run_takeover_mode(domain)
                input("\n  Press Enter to return to menu …")

        elif mode == "cors":
            url = ui.prompt_target("Target URL (e.g. https://api.example.com/user)")
            if url:
                run_cors_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "redirect":
            url = ui.prompt_target("Target URL (e.g. https://target.com/login?next=/dashboard)")
            if url:
                run_redirect_mode(url)
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

    elif args[0] == "fullscan":
        if len(args) < 2:
            ui.print_error("fullscan mode requires a target. Example: python main.py fullscan 192.168.1.1")
            sys.exit(1)
        ui.print_banner()
        run_full_scan_mode(args[1])

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

    elif args[0] == "subdomain":
        if len(args) < 2:
            ui.print_error("subdomain mode requires a domain. Example: python main.py subdomain example.com")
            sys.exit(1)
        ui.print_banner()
        run_subdomain_mode(args[1])

    elif args[0] == "takeover":
        if len(args) < 2:
            ui.print_error("takeover mode requires a domain. Example: python main.py takeover example.com")
            sys.exit(1)
        ui.print_banner()
        run_takeover_mode(args[1])

    elif args[0] == "cors":
        if len(args) < 2:
            ui.print_error("cors mode requires a URL. Example: python main.py cors https://api.example.com/user")
            sys.exit(1)
        ui.print_banner()
        run_cors_mode(args[1])

    elif args[0] == "redirect":
        if len(args) < 2:
            ui.print_error("redirect mode requires a URL. Example: python main.py redirect https://target.com/login")
            sys.exit(1)
        ui.print_banner()
        run_redirect_mode(args[1])

    else:
        ui.print_error(f"Unknown mode: '{args[0]}'")
        sys.exit(1)