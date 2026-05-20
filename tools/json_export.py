"""
tools/json_export.py
Exports FENRIR scan results to a structured JSON file for LOKI integration.

Output: result/scan_results.json
Schema is stable — LOKI reads this file on startup.
"""
import json
import os
import datetime
from config import REPORT_DIR

FENRIR_VERSION = "2.0.0"
EXPORT_PATH = os.path.join(REPORT_DIR, "scan_results.json")


def _port_num(port_str: str) -> int:
    try:
        return int(str(port_str).split("/")[0])
    except (ValueError, AttributeError):
        return 0


def export_full_scan(full_result: dict) -> str:
    """
    Convert a full_result dict (from run_full_scan_mode) into a LOKI-compatible
    JSON file.  Returns the path of the written file.
    """
    os.makedirs(REPORT_DIR, exist_ok=True)

    target      = full_result.get("target", "unknown")
    nmap_result = full_result.get("nmap_result", {})
    cve_results = full_result.get("cve_results", [])
    ssl_results = full_result.get("ssl_results", [])
    http_results = full_result.get("http_results", [])
    gobuster    = full_result.get("gobuster_result")
    waf_result  = full_result.get("waf_result")

    # ── Open ports ────────────────────────────────────────────────────────────
    from reports.report_generator import _parse_ports
    raw_out   = nmap_result.get("output", "")
    ports     = _parse_ports(raw_out)
    open_ports = [_port_num(p["port"]) for p in ports if p["state"] == "open"]

    # ── Services ──────────────────────────────────────────────────────────────
    services = []
    for p in ports:
        if p["state"] == "open":
            services.append({
                "port":     _port_num(p["port"]),
                "protocol": p["port"].split("/")[1] if "/" in p["port"] else "tcp",
                "service":  p["service"],
                "product":  p.get("product", p["service"]),
                "version":  p.get("version", ""),
            })

    # ── Vulnerabilities (unified list for LOKI) ───────────────────────────────
    vulnerabilities = []

    # CVEs
    for svc in cve_results:
        for cve in svc.cves:
            vulnerabilities.append({
                "type":        "cve",
                "port":        svc.port,
                "protocol":    svc.protocol,
                "service":     svc.service,
                "product":     svc.product,
                "version":     svc.version,
                "cve_id":      cve.cve_id,
                "severity":    cve.cvss_severity or "Unknown",
                "cvss":        cve.cvss_score,
                "description": cve.description[:200],
                "url":         cve.url,
                "verified":    getattr(cve, "confidence", "verified") == "verified",
            })

    # SSL/TLS issues
    ssl_issues = []
    for r in ssl_results:
        for f in r.findings:
            if f.severity == "Info":
                continue
            ssl_issues.append({
                "port":     r.port,
                "severity": f.severity,
                "title":    f.title,
                "detail":   f.detail,
            })
            if f.severity in ("Critical", "High", "Medium"):
                vulnerabilities.append({
                    "type":     "ssl",
                    "port":     r.port,
                    "severity": f.severity,
                    "title":    f.title,
                    "detail":   f.detail,
                })

    # HTTP header issues
    http_issues = []
    for r in http_results:
        for hf in r.missing_headers:
            http_issues.append({
                "url":            r.url,
                "header":         hf.name,
                "severity":       hf.severity,
                "recommendation": hf.recommendation,
            })
            if hf.severity in ("High", "Medium"):
                vulnerabilities.append({
                    "type":     "http_header",
                    "port":     _port_from_url(r.url),
                    "severity": hf.severity,
                    "title":    f"Missing header: {hf.name}",
                    "detail":   hf.recommendation,
                })

    # Gobuster high-interest paths
    gobuster_paths = []
    if gobuster and getattr(gobuster, "interesting_paths", None):
        from reports.report_generator import _path_severity
        for f in gobuster.interesting_paths:
            gobuster_paths.append({
                "path":     f.path,
                "status":   f.status,
                "size":     f.size,
                "redirect": f.redirect or "",
                "high_interest": bool(_path_severity(f.path)),
            })
            if _path_severity(f.path):
                vulnerabilities.append({
                    "type":     "directory",
                    "port":     _port_from_url(gobuster.target),
                    "severity": "High",
                    "title":    f"Sensitive path: {f.path}",
                    "detail":   "May expose admin interface, credentials, or source code",
                })

    # WAF
    waf_info = {"detected": False, "name": None, "confidence": None}
    if waf_result:
        waf_info = {
            "detected":   waf_result.detected,
            "name":       waf_result.waf_name or None,
            "confidence": waf_result.confidence or None,
        }

    # Sort vulnerabilities: Critical → High → Medium → Low
    _sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    vulnerabilities.sort(key=lambda v: _sev_order.get(v.get("severity", ""), 0), reverse=True)

    payload = {
        "fenrir_version": FENRIR_VERSION,
        "target":         target,
        "timestamp":      datetime.datetime.now().isoformat(),
        "scan_success":   nmap_result.get("success", False),
        "open_ports":     open_ports,
        "services":       services,
        "vulnerabilities": vulnerabilities,
        "ssl_issues":     ssl_issues,
        "http_issues":    http_issues,
        "gobuster_paths": gobuster_paths,
        "waf":            waf_info,
    }

    with open(EXPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return EXPORT_PATH


def _port_from_url(url: str) -> int:
    """Best-effort port extraction from a URL string."""
    if not url:
        return 0
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80
    except Exception:
        return 0
