# FENRIR
**Flexible Engine for Network Reconnaissance & Intelligent Red-teaming**

AI-powered, modular offensive security toolkit built for Bug Bounty reconnaissance and vulnerability assessment. Combines classic security tools with Claude AI and produces professional PDF reports.

---

## Tools

| # | Mode | Tool | What it does |
|---|---|---|---|
| 1 | `fullscan` | Full Scan | Nmap + CVE lookup + SSL/TLS + HTTP headers + optional Gobuster — all in one run |
| 2 | `nmap` | Nmap Scan | Port scan with service/version detection and automatic CVE lookup via NVD API |
| 3 | `gobuster` | Dir Bruteforce | Hidden path discovery on web servers |
| 4 | `subdomain` | Subdomain Enum | Finds subdomains via subfinder → amass → crt.sh → HackerTarget (auto-fallback) |
| 5 | `takeover` | Takeover Check | Detects dangling CNAME records pointing to unclaimed services (30+ fingerprints) |
| 6 | `cors` | CORS Scanner | Tests 7 crafted origins; detects Critical/High/Medium CORS misconfigurations |
| 7 | `redirect` | Open Redirect | Tests 29 redirect parameters with 9 bypass payloads; inspects Location header |
| 8 | `xss` | XSS Scanner | Injects 20 XSS payloads into every URL parameter; confirms unescaped reflection |
| 9 | `sqli` | SQLi Tester | Error-based (23 payloads, DB fingerprints) + boolean differential detection |
| r | `redteam` | AI Red-Team | Fires adversarial prompts against AI endpoints with CVSS scoring |

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
ENGINE=anthropic
ANTHROPIC_API_KEY=sk-ant-...
NVD_API_KEY=...        # optional — increases NVD rate limit
```

**Optional external tools** (improves subdomain enumeration):
- [subfinder](https://github.com/projectdiscovery/subfinder) — place at `C:\Tools\subfinder.exe`
- [gobuster](https://github.com/OJ/gobuster) — required for directory scan

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
python main.py redteam     MyBot
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
├── requirements.txt
│
├── tools/
│   ├── nmap_tool.py           # Nmap wrapper (5 scan types)
│   ├── cve_lookup.py          # NVD API v2 CVE lookup
│   ├── gobuster_tool.py       # Gobuster wrapper
│   ├── ssl_tool.py            # SSL/TLS certificate + cipher analysis
│   ├── http_headers_tool.py   # HTTP security header check
│   ├── subdomain_tool.py      # Subdomain enumeration
│   ├── takeover_checker.py    # Subdomain takeover detection
│   ├── cors_scanner.py        # CORS misconfiguration scanner
│   ├── redirect_scanner.py    # Open redirect scanner
│   ├── xss_scanner.py         # Reflected XSS scanner
│   └── sqli_tester.py         # SQL injection tester
│
├── ai_red_team/
│   ├── tester.py              # Red-team engine
│   ├── prompts.py             # 10 adversarial attack templates
│   └── cvss_scorer.py         # CVSS v3.1 scoring
│
├── reports/
│   └── report_generator.py    # PDF report generation (all tools)
│
├── security/
│   └── validator.py           # Scope validation
│
├── ui/
│   └── terminal.py            # Rich terminal UI
│
└── wordlists/
    └── common.txt             # Gobuster wordlist
```

---

## Tech Stack

- **Python 3.11+** · **Rich** (terminal UI) · **Requests** (HTTP)
- **python-nmap** · **dnspython** · **xhtml2pdf** · **markdown2**
- **Anthropic Claude API** (AI red-team engine)
- **NVD API v2** (CVE database)
