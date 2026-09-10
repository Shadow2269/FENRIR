"""
main.py — FENRIR
Flexible Engine for Network Reconnaissance & Intelligent Red-teaming
"""
import sys
import re
from ui import terminal as ui
from tools.nmap_tool import run_nmap
from reports.report_generator import (
    generate_nmap_report,
    generate_gobuster_report, generate_full_scan_report,
    generate_subdomain_report, generate_takeover_report,
    generate_cors_report, generate_redirect_report,
    generate_xss_report, generate_sqli_report,
    generate_waf_report, generate_dns_report,
    generate_http_methods_report, generate_ssrf_report,
    generate_lfi_report, generate_jwt_report, generate_xxe_report,
    generate_idor_report, generate_fingerprint_report, generate_param_report,
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
    total_steps = 7 if include_gobuster else 6

    full_result = {
        "target":          target,
        "nmap_result":     {},
        "cve_results":     [],
        "ssl_results":     [],
        "http_results":    [],
        "gobuster_result": None,
        "waf_result":      None,
    }

    # ── Step 1: Nmap ──────────────────────────────────────────────────────────
    ui.print_scan_step(1, total_steps, f"Nmap Service Scan — {target}")
    with ui.spinner(f"Scanning {target} …") as prog:
        task = prog.add_task("nmap -sV ...", total=None)
        nmap_result = run_nmap(target, flags=["-sV", "--version-intensity", "9"], confirmed=confirmed, timeout=180)
        prog.update(task, completed=True)

    full_result["nmap_result"] = nmap_result
    ui.print_nmap_result(nmap_result)

    if not nmap_result["success"]:
        ui.print_error(f"Nmap failed: {nmap_result['error']}")
        return

    services = parse_nmap_services(nmap_result["output"])
    ui.print_info(f"{len(services)} service(s) found")

    # ── Step 2: Version Enrichment ────────────────────────────────────────────
    ui.print_scan_step(2, total_steps, "Version Enrichment — active probing for hidden versions")
    from tools.version_probe import enrich_services
    no_version = [s for s in services if not s.get("version")]
    if no_version:
        ui.print_info(f"  {len(no_version)} service(s) have no version string — probing actively …")
        with ui.spinner("Probing for hidden versions …") as prog:
            task = prog.add_task("version probe", total=None)
            enrich_services(target, services)
            prog.update(task, completed=True)
        enriched = [s for s in services if s.get("version_probe_method")]
        if enriched:
            for svc in enriched:
                estimate_tag = " [estimate]" if svc.get("version_is_estimate") else ""
                ui.print_info(
                    f"  ✓  Port {svc['port']}: {svc.get('product', svc['service'])} "
                    f"{svc['version']}{estimate_tag}  (via {svc['version_probe_method']})"
                )

        # Services still without a version after active probing → offer nmap banner rescan
        still_missing = [s for s in services if not s.get("version")]
        if still_missing and ui.confirm_nmap_rescan([s["port"] for s in still_missing]):
            ports_str = ",".join(str(s["port"]) for s in still_missing)
            ui.print_info(f"  Re-scanning port(s) {ports_str} with --script=banner …")
            with ui.spinner(f"nmap banner rescan — {ports_str} …") as prog:
                task = prog.add_task("nmap --script=banner ...", total=None)
                rescan = run_nmap(
                    target,
                    flags=["-sV", "--version-intensity", "9", "--script=banner", "-p", ports_str],
                    confirmed=confirmed,
                    timeout=120,
                )
                prog.update(task, completed=True)
            if rescan["success"]:
                rescan_map = {s["port"]: s for s in parse_nmap_services(rescan["output"])}
                newly_found = 0
                for svc in still_missing:
                    rs = rescan_map.get(svc["port"])
                    if rs and rs.get("version"):
                        svc["version"]              = rs["version"]
                        svc["product"]              = rs.get("product") or svc["product"]
                        svc["version_probe_method"] = "nmap banner rescan"
                        newly_found += 1
                        ui.print_info(
                            f"  ✓  Port {svc['port']}: {svc['product']} {svc['version']}"
                            f"  (via nmap banner rescan)"
                        )
                if not newly_found:
                    ui.print_info("  Banner rescan found no additional versions.")
            else:
                ui.print_info(f"  Banner rescan failed: {rescan.get('error', 'unknown error')}")

        if not enriched and not [s for s in services if s.get("version_probe_method") == "nmap banner rescan"]:
            ui.print_info("  No additional versions found via active probing.")
    else:
        ui.print_info("  All services already have version strings — skipping active probing.")

    # ── Step 3: CVE Lookup ────────────────────────────────────────────────────
    ui.print_scan_step(3, total_steps, f"CVE Lookup ({len(services)} service(s))")
    if services:
        with ui.ScanProgress(total=len(services), label="CVE Lookup") as prog:
            for svc in services:
                label = f"{svc['product']} {svc['version']}".strip() or svc["service"]
                prog.advance(label)
                if not svc["version"]:
                    # Version hidden by server — skip CVE lookup for this service
                    full_result["cve_results"].append(ServiceCVEResult(
                        port=svc["port"], protocol=svc["protocol"],
                        service=svc["service"], product=svc["product"],
                        version="", cves=[],
                    ))
                    continue
                cves = lookup_cves(
                    f"{svc['product']} {svc['version']}",
                    product=svc["product"],
                    version=svc["version"],
                    api_key=NVD_API_KEY,
                )
                full_result["cve_results"].append(ServiceCVEResult(
                    port=svc["port"], protocol=svc["protocol"],
                    service=svc["service"], product=svc["product"],
                    version=svc["version"], cves=cves,
                    version_is_estimate=svc.get("version_is_estimate", False),
                ))
        total_cves = sum(len(r.cves) for r in full_result["cve_results"])
        ui.print_cve_results(full_result["cve_results"])
        ui.print_info(f"{total_cves} CVE(s) found")

    # ── Step 4: WAF Detection ─────────────────────────────────────────────────
    web_ports_early = _detect_web_ports(nmap_result["output"], target)
    ui.print_scan_step(4, total_steps, "WAF Detection")
    if web_ports_early:
        first_port_waf, first_https_waf = web_ports_early[0]
        scheme_waf = "https" if first_https_waf else "http"
        waf_url = f"{scheme_waf}://{target}:{first_port_waf}" if first_port_waf not in (80, 443) else f"{scheme_waf}://{target}"
        from tools.waf_detector import detect_waf
        with ui.spinner(f"WAF Detection {waf_url} …") as prog:
            task = prog.add_task("waf detect", total=None)
            waf_result = detect_waf(waf_url)
            prog.update(task, completed=True)
        full_result["waf_result"] = waf_result
        ui.print_waf_result(waf_result)
    else:
        ui.print_info("No HTTP/HTTPS ports found — skipping WAF detection.")

    # ── Step 5: SSL/TLS ───────────────────────────────────────────────────────
    tls_ports = _detect_tls_ports(nmap_result["output"])
    ui.print_scan_step(5, total_steps, f"SSL/TLS Analysis ({len(tls_ports)} port(s))")
    for port in tls_ports:
        ui.print_info(f"  Checking {target}:{port} …")
        ssl_res = check_ssl(target, port)
        full_result["ssl_results"].append(ssl_res)
    ui.print_ssl_results(full_result["ssl_results"])

    # ── Step 6: HTTP Security Headers ─────────────────────────────────────────
    web_ports = _detect_web_ports(nmap_result["output"], target)
    ui.print_scan_step(6, total_steps, f"HTTP Security Headers ({len(web_ports)} URL(s))")
    for port, is_https in web_ports:
        ui.print_info(f"  Checking {'https' if is_https else 'http'}://{target}:{port} …")
        http_res = check_http_headers(target, port, use_tls=is_https)
        full_result["http_results"].append(http_res)
    ui.print_http_header_results(full_result["http_results"])

    # ── Step 7: Gobuster (optional) ───────────────────────────────────────────
    if include_gobuster and web_ports:
        first_port, first_https = web_ports[0]
        scheme = "https" if first_https else "http"
        gobuster_url = (
            f"{scheme}://{target}/"
            if (first_https and first_port == 443) or (not first_https and first_port == 80)
            else f"{scheme}://{target}:{first_port}/"
        )
        ui.print_scan_step(7, total_steps, f"Directory Scan — {gobuster_url}")
        from tools.gobuster_tool import run_gobuster
        with ui.spinner(f"Gobuster — {gobuster_url} …") as prog:
            task = prog.add_task("gobuster dir ...", total=None)
            gobuster_result = run_gobuster(gobuster_url, wordlist=wordlist, confirmed=confirmed)
            prog.update(task, completed=True)
        full_result["gobuster_result"] = gobuster_result
        _print_gobuster_result(gobuster_result)
    elif include_gobuster:
        ui.print_info("No HTTP/HTTPS ports found — skipping Gobuster.")

    # ── Generate PDF report ───────────────────────────────────────────────────
    ui.print_info("Generating report …")
    path = generate_full_scan_report(full_result)
    ui.print_report_saved(path)

    # ── JSON Export for LOKI ──────────────────────────────────────────────────
    from tools.json_export import export_full_scan
    json_path = export_full_scan(full_result)
    ui.print_json_export(json_path)


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


# ── Mode: SQLi Tester ────────────────────────────────────────────────────────

def run_sqli_mode(url: str):
    from tools.sqli_tester import scan_sqli, _ERROR_PAYLOADS, _BOOL_TRUE, _extract_params
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    params = _extract_params(url) or {"id": ["1"]}
    ui.print_info(
        f"Testing {len(params)} parameter(s) — "
        f"{len(_ERROR_PAYLOADS)} error payloads + {len(_BOOL_TRUE)} boolean probes each"
    )

    with ui.spinner(f"SQLi scan {url} …") as prog:
        task = prog.add_task("sqli scan", total=None)
        result = scan_sqli(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_sqli_results(result)
    path = generate_sqli_report(result)
    ui.print_report_saved(path)


# ── Mode: XSS Scanner ────────────────────────────────────────────────────────

def run_xss_mode(url: str):
    from tools.xss_scanner import scan_xss, _PAYLOADS, _extract_params
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    params = _extract_params(url) or {"q": [""]}
    total = len(params) * len(_PAYLOADS)
    ui.print_info(
        f"Testing {len(params)} parameter(s) × {len(_PAYLOADS)} payloads "
        f"= {total} requests against: {url}"
    )

    with ui.spinner(f"XSS scan {url} …") as prog:
        task = prog.add_task("xss scan", total=None)
        result = scan_xss(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_xss_results(result)
    path = generate_xss_report(result)
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


# ── Mode: DNS Recon ──────────────────────────────────────────────────────────

def run_dns_mode(domain: str):
    from tools.dns_recon import run_dns_recon
    ui.print_info(f"DNS Recon: {domain}")
    with ui.spinner(f"WHOIS + DNS records {domain} …") as prog:
        task = prog.add_task("dns recon", total=None)
        result = run_dns_recon(domain)
        prog.update(task, completed=True)
    ui.print_dns_result(result)
    path = generate_dns_report(result)
    ui.print_report_saved(path)


# ── Mode: WAF Detection ───────────────────────────────────────────────────────

def run_waf_mode(url: str):
    from tools.waf_detector import detect_waf
    from security.validator import is_allowed_target
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or url
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
    with ui.spinner(f"WAF Detection {url} …") as prog:
        task = prog.add_task("waf detect", total=None)
        result = detect_waf(url)
        prog.update(task, completed=True)
    ui.print_waf_result(result)
    path = generate_waf_report(result)
    ui.print_report_saved(path)


# ── Mode: HTTP Methods ────────────────────────────────────────────────────────

def run_http_methods_mode(url: str):
    from tools.http_methods import test_http_methods
    from security.validator import is_allowed_target
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or url
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
    with ui.spinner(f"HTTP Methods {url} …") as prog:
        task = prog.add_task("http methods", total=None)
        result = test_http_methods(url)
        prog.update(task, completed=True)
    ui.print_http_methods_result(result)
    path = generate_http_methods_report(result)
    ui.print_report_saved(path)


# ── Mode: SSRF ────────────────────────────────────────────────────────────────

def run_ssrf_mode(url: str):
    from tools.ssrf_tester import test_ssrf
    from security.validator import is_allowed_target
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or url
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
    with ui.spinner(f"SSRF scan {url} …") as prog:
        task = prog.add_task("ssrf scan", total=None)
        result = test_ssrf(url)
        prog.update(task, completed=True)
    ui.print_ssrf_result(result)
    path = generate_ssrf_report(result)
    ui.print_report_saved(path)


# ── Mode: LFI ─────────────────────────────────────────────────────────────────

def run_lfi_mode(url: str):
    from tools.lfi_scanner import scan_lfi
    from security.validator import is_allowed_target
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or url
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
    with ui.spinner(f"LFI scan {url} …") as prog:
        task = prog.add_task("lfi scan", total=None)
        result = scan_lfi(url)
        prog.update(task, completed=True)
    ui.print_lfi_result(result)
    path = generate_lfi_report(result)
    ui.print_report_saved(path)


# ── Mode: JWT ─────────────────────────────────────────────────────────────────

def run_jwt_mode(token: str):
    from tools.jwt_analyzer import analyze_jwt
    with ui.spinner("Analysing JWT …") as prog:
        task = prog.add_task("jwt analyze", total=None)
        result = analyze_jwt(token)
        prog.update(task, completed=True)
    ui.print_jwt_result(result)
    path = generate_jwt_report(result)
    ui.print_report_saved(path)


# ── Mode: XXE ─────────────────────────────────────────────────────────────────

def run_xxe_mode(url: str):
    from tools.xxe_scanner import scan_xxe
    from security.validator import is_allowed_target
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    host = urlparse(url).hostname or url
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
    with ui.spinner(f"XXE scan {url} …") as prog:
        task = prog.add_task("xxe scan", total=None)
        result = scan_xxe(url)
        prog.update(task, completed=True)
    ui.print_xxe_result(result)
    path = generate_xxe_report(result)
    ui.print_report_saved(path)


# ── Mode: IDOR Detector ───────────────────────────────────────────────────────

def run_idor_mode(url: str):
    from tools.idor_tester import test_idor
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    auth = ui.prompt_target("Authorization header (e.g. Bearer <token>) — leave empty to skip").strip()

    ui.print_info(f"Probing numeric IDs in path segments and query params of: {url}")

    with ui.spinner(f"IDOR scan {url} …") as prog:
        task = prog.add_task("idor scan", total=None)
        result = test_idor(url, auth_header=auth, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_idor_result(result)
    path = generate_idor_report(result)
    ui.print_report_saved(path)


# ── Mode: Technology Fingerprint ─────────────────────────────────────────────

def run_fingerprint_mode(url: str):
    from tools.fingerprint_tool import fingerprint
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

    ui.print_info(f"Fingerprinting: {url}")

    with ui.spinner(f"Fingerprinting {url} …") as prog:
        task = prog.add_task("fingerprint", total=None)
        result = fingerprint(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_fingerprint_result(result)
    path = generate_fingerprint_report(result)
    ui.print_report_saved(path)


# ── Mode: Parameter Discovery ────────────────────────────────────────────────

def run_param_discovery_mode(url: str):
    from tools.param_discovery import discover_params, _load_wordlist
    from security.validator import is_allowed_target
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    host = urlparse(url).hostname or url
    confirmed = False
    if not is_allowed_target(host):
        if not ui.confirm_scan_target(url):
            ui.print_error("Scan abgebrochen — keine Autorisierung.")
            return
        confirmed = True

    wordlist = _load_wordlist()
    total_tests = len(wordlist) * 2  # GET + POST
    ui.print_info(
        f"Testing {len(wordlist)} parameter names × 2 methods "
        f"= {total_tests} probes against: {url}"
    )

    with ui.spinner(f"Param discovery {url} …") as prog:
        task = prog.add_task("param discovery", total=None)
        result = discover_params(url, confirmed=confirmed)
        prog.update(task, completed=True)

    ui.print_param_result(result)
    path = generate_param_report(result)
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

        elif mode == "xss":
            url = ui.prompt_target("Target URL with params (e.g. http://target.com/search?q=test)")
            if url:
                run_xss_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "sqli":
            url = ui.prompt_target("Target URL with params (e.g. http://target.com/items?id=1)")
            if url:
                run_sqli_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "dns":
            domain = ui.prompt_target("Target domain (e.g. example.com)")
            if domain:
                run_dns_mode(domain)
                input("\n  Press Enter to return to menu …")

        elif mode == "waf":
            url = ui.prompt_target("Target URL (e.g. https://example.com)")
            if url:
                run_waf_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "httpmethods":
            url = ui.prompt_target("Target URL (e.g. https://example.com/api/resource)")
            if url:
                run_http_methods_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "ssrf":
            url = ui.prompt_target("Target URL with params (e.g. http://target.com/fetch?url=http://x)")
            if url:
                run_ssrf_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "lfi":
            url = ui.prompt_target("Target URL with params (e.g. http://target.com/page?file=home)")
            if url:
                run_lfi_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "jwt":
            token = ui.prompt_target("JWT token (paste full token)")
            if token:
                run_jwt_mode(token)
                input("\n  Press Enter to return to menu …")

        elif mode == "xxe":
            url = ui.prompt_target("Target URL (XML endpoint, e.g. https://target.com/api/xml)")
            if url:
                run_xxe_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "idor":
            url = ui.prompt_target("Target URL with numeric ID (e.g. http://target.com/api/user/100)")
            if url:
                run_idor_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "fingerprint":
            url = ui.prompt_target("Target URL (e.g. https://target.com)")
            if url:
                run_fingerprint_mode(url)
                input("\n  Press Enter to return to menu …")

        elif mode == "paramdiscovery":
            url = ui.prompt_target("Target URL (e.g. http://target.com/api/endpoint)")
            if url:
                run_param_discovery_mode(url)
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

    elif args[0] == "xss":
        if len(args) < 2:
            ui.print_error("xss mode requires a URL. Example: python main.py xss http://target.com/search?q=test")
            sys.exit(1)
        ui.print_banner()
        run_xss_mode(args[1])

    elif args[0] == "sqli":
        if len(args) < 2:
            ui.print_error("sqli mode requires a URL. Example: python main.py sqli http://target.com/items?id=1")
            sys.exit(1)
        ui.print_banner()
        run_sqli_mode(args[1])

    else:
        ui.print_error(f"Unknown mode: '{args[0]}'")
        sys.exit(1)