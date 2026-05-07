# FENRIR 🐺
Flexible Engine for Network Reconnaissance & Intelligent Red-teaming

AI-powered security tool combining nmap scanning, CVE lookup 
and automated AI red-teaming with CVSS scoring.

## Features
- nmap scan + automatic CVE lookup via NVD API
- AI red-team tester for chatbots (jailbreak, injection, extraction…)
- CVSS v3.1 scoring for all findings
- Markdown + HTML reports
- Rich terminal UI

## Setup
pip install -r requirements.txt
cp .env.example .env   # API Keys eintragen
install gobuster.exe and put it in ../SecurityTool

## Usage
python main.py