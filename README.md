# FENRIR
**Flexible Engine for Network Reconnaissance & Intelligent Red-teaming**

Modular offensive security toolkit built for Bug Bounty reconnaissance and vulnerability assessment. Produces professional PDF reports.

---

## Tools

| Key | Mode | Tool | What it does |
|---|---|---|---|
| 1 | `fullscan` | Full Scan | Nmap + CVE lookup + SSL/TLS + HTTP headers + WAF + optional Gobuster — all in one run, exports JSON for LOKI |
| 2 | `nmap` | Nmap Scan | Port scan with service/version detection and automatic CVE lookup via NVD API |
| 3 | `gobuster` | Dir Bruteforce | Hidden path discovery on web servers |
| 4 | `subdomain` | Subdomain Enum | Finds subdomains via subfinder → amass → crt.sh → HackerTarget (auto-fallback) |
| 5 | `takeover` | Takeover Check | Detects dangling CNAME records pointing to unclaimed services (30+ fingerprints) |
| 6 | `cors` | CORS Scanner | Tests 7 crafted origins; detects Critical/High/Medium CORS misconfigurations |
| 7 | `redirect` | Open Redirect | Tests 29 redirect parameters with 9 bypass payloads; inspects Location header |
| 8 | `xss` | XSS Scanner | Injects 20 XSS payloads into every URL parameter; confirms unescaped reflection |
| 9 | `sqli` | SQLi Tester | Error-based (23 payloads, DB fingerprints) + boolean differential detection |
| a | `dns` | DNS Recon | WHOIS + A/MX/NS/TXT/CNAME records + zone transfer attempt (AXFR) |
| b | `waf` | WAF Detection | Fingerprints web application firewalls via headers and malicious probes |
| c | `httpmethods` | HTTP Methods | Tests which HTTP methods are enabled (PUT, DELETE, TRACE, OPTIONS, …) |
| d | `ssrf` | SSRF Scanner | Inband SSRF detection via cloud-metadata and internal IP payloads |
| e | `lfi` | LFI Scanner | Path traversal and file inclusion detection (LFI + RFI payloads) |
| f | `jwt` | JWT Analyzer | Tests alg:none, weak secret bruteforce, RS256→HS256 confusion, expired tokens, PII in payload |
| g | `xxe` | XXE Scanner | Sends XXE payloads to XML endpoints; detects inband file leakage |
| h | `idor` | IDOR Detector | Probes numeric IDs in URL path segments and query params (±1/5/10/50/100 offsets) |
| i | `fingerprint` | Tech Fingerprint | Identifies server, CMS, framework, language and frontend via headers, body patterns, cookies and favicon hash |
| j | `paramdiscovery` | Param Discovery | Brute-forces 300 hidden GET/POST parameters via response-length differential |

Every tool produces a **PDF report** saved to the `result/` directory.

---

## Setup

**Requirements:** Python 3.11+, Windows or Linux

```bash
pip install -r requirements.txt
```

Copy the example env file and fill in your API keys:

```bash
cp .env.example .env
```

```env
NVD_API_KEY=...        # optional — increases NVD rate limit
```

**Optional external tools** (improves subdomain enumeration):
- [subfinder](https://github.com/projectdiscovery/subfinder) — place at `C:\Tools\subfinder.exe`
- [gobuster](https://github.com/OJ/gobuster) — required for directory scan

---

## OPSEC Mode

Set `OPSEC_MODE=true` in `.env` to enable stealth settings for internal scans:

| Setting | Normal | OPSEC |
|---|---|---|
| Nmap timing | `-T4` / `-T3` | `-T1 --scan-delay 2s --randomize-hosts` |
| Gobuster threads | 10 | 1 |
| Gobuster delay | none | `--delay 1000ms` |
| User-Agent | `Mozilla/5.0 (FENRIR security scanner)` | Chrome 124 on Windows 10 |
| Inter-request delay | none | `OPSEC_DELAY` seconds (default 2.0) |

The banner turns orange and shows an OPSEC warning when active.

```env
OPSEC_MODE=true
OPSEC_DELAY=2.0   # seconds between HTTP requests
```

---

## Usage

### Interactive menu
```bash
python main.py
```

### Direct CLI
```bash
python main.py fullscan    scanme.nmap.org
python main.py nmap        192.168.1.1
python main.py gobuster    http://192.168.1.1
python main.py subdomain   example.com
python main.py takeover    example.com
python main.py cors        https://api.example.com/user
python main.py redirect    https://target.com/login
python main.py xss         http://target.com/search?q=test
python main.py sqli        http://target.com/items?id=1
```

---

## Scope & Authorization

FENRIR enforces a scope allowlist before every scan. Targets outside the list require manual confirmation.

Default allowed targets (edit `config.py`):
```
127.0.0.1
192.168.0.0/16
10.0.0.0/8
scanme.nmap.org
```

**Only scan targets you are authorized to test.**

---

## Project Structure

```
SecurityTool/
├── main.py                    # Entry point + mode dispatcher
├── config.py                  # Central config (.env-based)
├── opsec.py                   # OPSEC helper: stealth UA + inter-request sleep
├── requirements.txt
│
├── tools/
│   ├── nmap_tool.py           # Nmap wrapper (5 scan types, OPSEC-aware)
│   ├── cve_lookup.py          # NVD API v2 CVE lookup
│   ├── gobuster_tool.py       # Gobuster wrapper (OPSEC-aware)
│   ├── ssl_tool.py            # SSL/TLS certificate + cipher analysis
│   ├── http_headers_tool.py   # HTTP security header check
│   ├── subdomain_tool.py      # Subdomain enumeration
│   ├── takeover_checker.py    # Subdomain takeover detection (30+ fingerprints)
│   ├── cors_scanner.py        # CORS misconfiguration scanner
│   ├── redirect_scanner.py    # Open redirect scanner
│   ├── xss_scanner.py         # Reflected XSS scanner (20 payloads)
│   ├── sqli_tester.py         # SQL injection tester (error + boolean)
│   ├── waf_detector.py        # WAF fingerprinting
│   ├── dns_recon.py           # WHOIS + DNS records + zone transfer
│   ├── http_methods.py        # HTTP method enumeration
│   ├── ssrf_tester.py         # SSRF inband detection
│   ├── lfi_scanner.py         # LFI/RFI path traversal scanner
│   ├── jwt_analyzer.py        # JWT vulnerability analysis
│   ├── xxe_scanner.py         # XXE injection scanner
│   ├── idor_tester.py         # IDOR detector (ID offset probing)
│   ├── fingerprint_tool.py    # Technology fingerprinting
│   ├── param_discovery.py     # Hidden parameter discovery (300-name wordlist)
│   ├── version_probe.py       # Active version probing for hidden service versions
│   └── json_export.py         # Structured JSON export for LOKI
│
├── reports/
│   └── report_generator.py    # PDF report generation (all tools)
│
├── security/
│   └── validator.py           # Scope validation
│
├── ui/
│   └── terminal.py            # Rich terminal UI (v2.2.0)
│
└── wordlists/
    ├── common.txt             # Gobuster wordlist
    └── params.txt             # Parameter discovery wordlist (300 names)
```

---

## Tech Stack

- **Python 3.11+** · **Rich** (terminal UI) · **Requests** (HTTP)
- **dnspython** · **python-whois** · **xhtml2pdf** · **markdown2**
- **NVD API v2** (CVE database)
