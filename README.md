<div align="center">

# 🛡️ WAPT Framework
### Web Application Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

**A modular, async web application security scanner built from scratch.**  
Covers the full pentest lifecycle — recon → scanning → exploitation → professional PDF reports.

[Features](#-features) · [Quick Start](#-quick-start) · [Architecture](#-architecture) · [API Docs](#-api-reference) · [Plugins](#-plugin-system) · [Legal](#%EF%B8%8F-legal--ethics)

---

> ⚠️ **AUTHORIZED USE ONLY** — Only scan targets you have explicit written permission to test.  
> Unauthorized penetration testing is illegal.

</div>

---

## 📋 Table of Contents

- [What Is This?](#-what-is-this)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Phase Breakdown](#-phase-breakdown)
- [CLI Reference](#-cli-reference)
- [API Reference](#-api-reference)
- [Plugin System](#-plugin-system)
- [Report Formats](#-report-formats)
- [Safe Test Targets](#-safe-test-targets)
- [Deployment (Free Public)](#-free-public-deployment)
- [Configuration](#-configuration)
- [Legal & Ethics](#%EF%B8%8F-legal--ethics)
- [Contributing](#-contributing)

---

## 🔍 What Is This?

WAPT Framework is a **complete penetration testing platform** built entirely in Python. It automates security testing of web applications across 6 phases:

```
Recon → Attack Surface Mapping → Vulnerability Testing → Reporting
```

Think of it as a self-hosted, open-source alternative to Burp Suite — built from scratch so you understand every line.

**What it finds:**
- SQL Injection (error-based, blind, time-based)
- Cross-Site Scripting (reflected, stored, DOM)
- Broken Authentication (default creds, no lockout, JWT flaws)
- IDOR (Insecure Direct Object References)
- Security Misconfigurations (TRACE, verbose errors, debug endpoints)
- Missing Security Headers (HSTS, CSP, X-Frame-Options, and more)
- DNS misconfigurations (zone transfer, missing SPF)
- Subdomain Takeover vulnerabilities
- Secrets in JavaScript files
- Directory listing, exposed backups, .env files

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Recon** | DNS records, WHOIS, subdomain enumeration (CT logs + bruteforce), tech fingerprinting |
| 🗺️ **Surface Mapping** | Port scanning (Nmap), directory bruteforcing, web crawling, form extraction |
| 💉 **Vuln Testing** | SQLi, XSS, Auth, IDOR, Misconfig — tests every form & URL parameter |
| 📊 **Reports** | Professional PDF, HTML, JSON, Markdown reports with CVSS scores |
| 🔌 **Plugin System** | Drop a `.py` file in `plugins/` — auto-discovered, no code changes needed |
| 🥷 **Stealth Modes** | Normal / Polite / Stealth — randomized delays, UA rotation, header evasion |
| 🌐 **REST API** | Full FastAPI backend with Swagger UI at `/api/docs` |
| 🖥️ **Dashboard** | React frontend — manage targets, launch scans, view findings live |
| 🐳 **Docker** | One-command deployment with `docker-compose up` |
| 🔒 **Safe by Design** | Scope enforcer, always-blocked list, rate limiting, audit logging |

---

## 🛠️ Tech Stack

**Backend**
- Python 3.11+ with `asyncio` for concurrent scanning
- FastAPI + Uvicorn (REST API)
- SQLAlchemy 2.0 async (ORM)
- SQLite (dev) / PostgreSQL (prod)
- httpx + aiohttp (async HTTP)
- dnspython, python-whois (recon)
- python-nmap (port scanning)
- WeasyPrint + Jinja2 (PDF/HTML reports)

**Frontend**
- React 18 + Vite
- React Query (server state)
- React Router v6
- Recharts (severity charts)
- Lucide React (icons)

**Infrastructure**
- Docker + Docker Compose
- Loguru (structured logging)
- Rich (terminal output)
- Click (CLI framework)

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.11+
python --version

# Node.js 18+ (for frontend)
node --version

# Nmap (optional but recommended for port scanning)
# Linux:   sudo apt install nmap
# macOS:   brew install nmap
# Windows: https://nmap.org/download.html
```

### 1 — Clone and Install

```bash
git clone https://github.com/yourusername/wapt-framework.git
cd wapt-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2 — Configure

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings (defaults work for local dev)
nano .env
```

### 3 — Start the Backend

```bash
# Option A: Using the CLI (recommended)
python cli.py server

# Option B: Using uvicorn directly
uvicorn main:app --reload --port 8000
```

API is now live at `http://localhost:8000`  
Swagger UI at `http://localhost:8000/api/docs`

### 4 — Start the Frontend (optional)

```bash
cd ui
npm install
npm run dev
# Dashboard at http://localhost:5173
```

### 5 — Run Your First Scan

```bash
# Scan a safe public test target
python cli.py scan http://testphp.vulnweb.com --type recon

# Full scan
python cli.py scan http://testphp.vulnweb.com --type full

# Generate reports
python cli.py report <scan-id> --format all
```

### Docker (One Command)

```bash
docker-compose up --build
# Backend:   http://localhost:8000
# Frontend:  http://localhost:5173
```

---

## 🏗️ Architecture

```
wapt-framework/
├── core/                    # Core engine
│   ├── engine.py            # Scan orchestrator — runs all modules
│   ├── scope.py             # Scope enforcer — prevents out-of-scope testing
│   ├── session.py           # HTTP session wrapper
│   ├── config.py            # Settings loader (.env + config.yaml)
│   ├── stealth.py           # Rate limiting + request evasion
│   └── security.py          # API auth + audit logging
│
├── modules/
│   ├── recon/               # Phase 2: Passive intelligence
│   │   ├── dns.py           # DNS records + zone transfer
│   │   ├── subdomain.py     # CT logs + DNS bruteforce
│   │   ├── tech_detect.py   # Stack fingerprinting
│   │   ├── whois_lookup.py  # Domain ownership
│   │   └── headers.py       # Security header audit
│   │
│   ├── scanner/             # Phase 3: Active mapping
│   │   ├── port_scan.py     # Nmap port scanner
│   │   ├── dir_brute.py     # Directory/file bruteforcer
│   │   ├── crawler.py       # BFS web crawler
│   │   └── form_extractor.py # Input registry builder
│   │
│   ├── vulns/               # Phase 4: Vulnerability testing
│   │   ├── sqli.py          # SQL injection (3 techniques)
│   │   ├── xss.py           # XSS (canary + payload escalation)
│   │   ├── auth.py          # Auth testing + JWT analysis
│   │   ├── idor.py          # Object reference manipulation
│   │   └── misconfig.py     # Server misconfiguration
│   │
│   └── reporter/            # Phase 5: Report generation
│       ├── collector.py     # DB aggregator + statistics
│       ├── html_report.py   # HTML + PDF via WeasyPrint
│       ├── exporters.py     # JSON + Markdown
│       └── templates/
│           └── report.html  # Jinja2 report template
│
├── api/                     # FastAPI REST API
│   ├── routes/
│   │   ├── targets.py       # /api/targets CRUD
│   │   ├── scans.py         # /api/scans CRUD + findings
│   │   └── reports.py       # /api/reports generate + download
│   └── models/schemas.py    # Pydantic request/response models
│
├── db/
│   ├── database.py          # Async SQLAlchemy engine
│   └── models.py            # Target, Scan, Finding, RequestLog tables
│
├── plugins/                 # Plugin system
│   ├── base.py              # WAPTPlugin base class
│   ├── loader.py            # Auto-discovery engine
│   └── example_open_redirect.py
│
├── payloads/                # Attack payloads
│   ├── sqli.yaml
│   ├── xss.yaml
│   ├── auth_wordlist.yaml
│   └── wordlists/
│
├── ui/                      # React dashboard
├── cli.py                   # CLI entry point
├── main.py                  # FastAPI app
├── config.yaml              # Default configuration
├── docker-compose.yml
└── requirements.txt
```

---

## 📦 Phase Breakdown

### Phase 1 — Foundation
Core engine, database models, config system, CLI with Click, FastAPI with health routes and CORS.

### Phase 2 — Reconnaissance
| Module | What It Does | Key Findings |
|--------|-------------|--------------|
| `dns.py` | Resolves A/MX/NS/TXT/CNAME/SOA records, attempts AXFR zone transfer | Zone transfer = High severity |
| `subdomain.py` | CT log queries (crt.sh) + DNS wordlist bruteforce | Subdomain takeover detection |
| `tech_detect.py` | Header/cookie/body pattern matching against 20+ signatures | WAF detection, version disclosure |
| `whois_lookup.py` | Domain registration, expiry, privacy status | Expiring domains = Critical |
| `headers.py` | Audits 7 security headers + cookie flags | Missing HSTS/CSP = High |

### Phase 3 — Active Scanner
| Module | What It Does |
|--------|-------------|
| `port_scan.py` | Nmap SYN scan with service detection, flags risky services (Redis, MongoDB, RDP) |
| `dir_brute.py` | 200+ paths tested, soft-404 detection via fingerprinting |
| `crawler.py` | BFS up to 200 pages/depth 5, extracts forms, params, JS files, emails, comments |
| `form_extractor.py` | Builds structured input registry consumed by Phase 4 modules |

### Phase 4 — Vulnerability Testing
| Module | Techniques | Severity |
|--------|------------|----------|
| `sqli.py` | Error-based, Boolean-blind, Time-based | Critical (CVSS 9.1–9.8) |
| `xss.py` | Canary reflection, context detection, payload escalation | High (CVSS 8.2) |
| `auth.py` | Default creds, lockout detection, username enumeration, JWT analysis | Critical–Medium |
| `idor.py` | Numeric/UUID/ObjectID manipulation, response comparison | High (CVSS 8.1) |
| `misconfig.py` | TRACE method, verbose errors, debug endpoints, dir listing | Medium–High |

### Phase 5 — Reporting
- **HTML** — Self-contained, browser-ready with severity charts
- **PDF** — Print-ready via WeasyPrint with page numbers and cover page
- **JSON** — Machine-readable for SIEM/Jira integration
- **Markdown** — Paste directly into GitHub issues or Confluence

### Phase 6 — Platform
Plugin system with auto-discovery, three stealth modes, API authentication, React dashboard, Docker deployment.

---

## 💻 CLI Reference

```bash
# Show all commands
python cli.py --help

# Show current configuration
python cli.py info

# Start API server
python cli.py server

# Run a scan
python cli.py scan <URL> [OPTIONS]

# Generate reports
python cli.py report <SCAN_ID> [OPTIONS]
```

### Scan Options

```bash
python cli.py scan <URL> \
  --type    [full|recon|scan|vuln|auth]  # Default: full
  --stealth [normal|polite|stealth]       # Default: normal
  --rate-limit <int>                      # Requests/second
  --timeout  <int>                        # Seconds per request
```

### Stealth Modes

| Mode | Delay | Concurrency | UA Rotation | Use For |
|------|-------|-------------|-------------|---------|
| `normal` | 0–0.2s | 20 parallel | No | Internal/CTF targets |
| `polite` | 0.5–2s | 5 parallel | Yes | Client engagements |
| `stealth` | 2–8s + jitter | 2 parallel | Yes + headers | WAF/IDS bypass |

### Examples

```bash
# Quick recon
python cli.py scan http://testphp.vulnweb.com --type recon

# Full scan, polite mode
python cli.py scan https://target.com --type full --stealth polite

# Stealth mode, slow rate
python cli.py scan https://target.com --type full --stealth stealth --rate-limit 1

# Generate all report formats
python cli.py report 8a6d0172-847c-403c-a515-2555efd2b4a2 --format all

# PDF only
python cli.py report <scan-id> --format pdf
```

---

## 🌐 API Reference

Base URL: `http://localhost:8000/api`  
Interactive docs: `http://localhost:8000/api/docs`

### Targets

```
POST   /targets/           Create a new target
GET    /targets/           List all targets
GET    /targets/{id}       Get a target
DELETE /targets/{id}       Soft-delete a target
```

### Scans

```
POST   /scans/             Create a scan record
GET    /scans/             List all scans
GET    /scans/{id}         Get scan status
GET    /scans/{id}/findings  Get all findings for a scan
```

### Reports

```
POST   /reports/generate          Generate reports (async)
GET    /reports/list              List generated files
GET    /reports/{scan_id}/summary Quick JSON summary
GET    /reports/download/{file}   Download a report file
```

### Health

```
GET    /health             Server health check
GET    /docs               Swagger UI
GET    /redoc              ReDoc documentation
```

### Example Requests

```bash
# Health check
curl http://localhost:8000/api/health

# Create target
curl -X POST http://localhost:8000/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","url":"http://testphp.vulnweb.com","scope_notes":"Public test target"}'

# Generate reports
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"scan_id":"<your-scan-id>","formats":["html","pdf","json","markdown"]}'
```

---

## 🔌 Plugin System

Extend the framework without touching core code. Drop a `.py` file in `plugins/` — it auto-loads on the next scan.

### Minimal Plugin

```python
# plugins/my_check.py
from plugins.base import WAPTPlugin
import httpx

class MyCheckPlugin(WAPTPlugin):
    name        = "my_check"           # unique ID
    version     = "1.0.0"
    author      = "Your Name"
    description = "What this plugin checks"
    category    = "vuln"               # recon | scanner | vuln | custom

    async def run(self) -> list:
        findings = []
        # ... your scanning logic ...
        # Use self.engine.target_url, self.engine.session, etc.
        findings.append(self.make_finding(
            title="Issue Found",
            severity="medium",
            vuln_type="my_check",
            url=self.engine.target_url,
            description="Description of the issue",
            evidence="What was observed",
            remediation="How to fix it",
            cvss_score=5.3,
        ))
        return findings
```

### What Plugins Can Access

| Attribute | Description |
|-----------|-------------|
| `self.engine.target_url` | Target URL being tested |
| `self.engine.scope` | Scope enforcer — check URLs before testing |
| `self.engine.session` | Pre-configured async HTTP client |
| `self.engine.input_registry` | All forms and URL params from crawler |
| `self.config` | Framework configuration (rate limits, UA strings) |
| `self.make_finding()` | Helper to build correctly structured findings |

### Example Plugins to Build

| Plugin | What It Tests |
|--------|--------------|
| `clickjacking.py` | Missing X-Frame-Options / CSP frame-ancestors |
| `open_redirect.py` | Redirect parameter injection (example included) |
| `path_traversal.py` | `../../../etc/passwd` in file parameters |
| `ssrf.py` | Internal URL injection in user-controlled params |
| `xxe.py` | XML External Entity in file upload endpoints |
| `cors_misconfig.py` | Wildcard CORS or trust of arbitrary origins |
| `graphql_introspection.py` | Exposed GraphQL schema |

---

## 📄 Report Formats

Every scan produces four report formats automatically:

```bash
python cli.py report <scan-id> --format all
# Creates:
#   WAPT-XXXXXXXX-20260409.html     (full visual report)
#   WAPT-XXXXXXXX-20260409.pdf      (print-ready)
#   WAPT-XXXXXXXX-20260409.json     (machine-readable)
#   WAPT-XXXXXXXX-20260409.md       (Markdown for GitHub/Jira)
```

**Report sections:**
- Cover page with overall risk rating
- Executive summary (plain English for non-technical readers)
- Scan metadata
- Severity distribution chart (donut chart)
- OWASP Top 10 coverage mapping
- Full finding cards (description + payload + evidence + remediation)
- Remediation priority table

---

## 🎯 Safe Test Targets

**Always legal to test — no permission needed:**

```bash
# Live intentionally-vulnerable sites
python cli.py scan http://testphp.vulnweb.com --type full
python cli.py scan http://testhtml5.vulnweb.com --type full
python cli.py scan http://testasp.vulnweb.com --type full

# Run locally with Docker
docker run -d -p 8080:80 vulnerables/web-dvwa
python cli.py scan http://localhost:8080 --type full

docker run -d -p 3000:3000 bkimminich/juice-shop
python cli.py scan http://localhost:3000 --type full

docker run -d -p 8888:8080 webgoat/webgoat
python cli.py scan http://localhost:8888 --type full
```

---

## 🌍 Free Public Deployment

Run WAPT Framework publicly for free so others can test it or so you can run scans remotely.

### Option 1 — Railway (Recommended, Easiest)

```bash
# 1. Push your project to GitHub
git push origin main

# 2. Go to railway.app → New Project → Deploy from GitHub repo
# 3. Railway auto-detects Dockerfile and deploys
# 4. Set environment variables in Railway dashboard:
#    APP_ENV=production
#    SECRET_KEY=your-long-random-key
#    DATABASE_URL=sqlite+aiosqlite:///./wapt.db

# Free tier: 500 hours/month, $5 credit
# Your API: https://wapt-production.up.railway.app
```

### Option 2 — Render

```bash
# 1. Go to render.com → New → Web Service → Connect GitHub repo
# 2. Settings:
#    Build Command: pip install -r requirements.txt
#    Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
# 3. Add environment variables in Render dashboard
# 4. Free tier: 750 hours/month (sleeps after 15min inactivity)
# Your API: https://wapt-framework.onrender.com
```

### Option 3 — Fly.io (Best Performance Free Tier)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# From project root
fly launch              # auto-detects Dockerfile, creates fly.toml
fly deploy

# Set secrets
fly secrets set SECRET_KEY=your-long-random-key
fly secrets set APP_ENV=production

# Free tier: 3 shared VMs, 3GB storage, 160GB bandwidth/month
# Your API: https://wapt-framework.fly.dev
```

**`fly.toml`** (created by `fly launch`, adjust if needed):
```toml
app = "wapt-framework"
primary_region = "sin"   # Singapore — closest to Bangladesh

[build]

[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true

[[vm]]
  memory = "512mb"
  cpu_kind = "shared"
  cpus = 1
```

### Option 4 — Oracle Cloud Always Free (Most Powerful)

Oracle gives **permanent** free VMs — no credit card expiry, no sleep:

```bash
# 1. Sign up at cloud.oracle.com (free, needs credit card for verification only)
# 2. Create "Always Free" VM:
#    Shape: VM.Standard.A1.Flex (4 OCPU, 24GB RAM ARM)
#    OS: Ubuntu 22.04

# 3. SSH into your VM
ssh ubuntu@<your-vm-ip>

# 4. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu

# 5. Clone your project
git clone https://github.com/yourusername/wapt-framework.git
cd wapt-framework

# 6. Start with Docker Compose
docker-compose up -d

# 7. Open firewall ports in Oracle dashboard: 8000, 5173

# Your API: http://<your-ip>:8000  (permanent, never sleeps, free forever)
```

### Option 5 — ngrok (Instant Public URL, No Deployment)

Expose your local server publicly in 30 seconds:

```bash
# Install ngrok: https://ngrok.com/download
# Start your local server first
python cli.py server

# In another terminal — expose port 8000
ngrok http 8000

# You get: https://abc123.ngrok.io → your localhost:8000
# Share this URL — anyone can use your API
# Free tier: 1 tunnel, 40 connections/min, URL changes each restart
```

### Frontend Deployment (Netlify — Free)

```bash
# Build the React app
cd ui
npm run build           # creates ui/dist/

# Deploy to Netlify
# Option A: Drag and drop ui/dist/ to netlify.com/drop
# Option B: CLI
npm install -g netlify-cli
netlify deploy --dir=dist --prod

# Set your API URL in ui/.env.production:
VITE_API_URL=https://your-backend-url.fly.dev/api

# Your dashboard: https://wapt-framework.netlify.app
```

### Summary: Best Free Stack

| Component | Platform | Free Tier |
|-----------|----------|-----------|
| Backend API | Fly.io | 3 VMs, never sleeps |
| Frontend | Netlify | Unlimited static hosting |
| Database | Built-in SQLite | Included |
| Total cost | | **$0** |

---

## ⚙️ Configuration

### config.yaml

```yaml
scan:
  default_rate_limit: 5      # requests/second
  default_timeout: 10        # seconds per request
  max_redirects: 5

scope:
  always_blocked:            # can NEVER be scanned
    - "google.com"
    - "amazon.com"
    - "cloudflare.com"
```

### .env Variables

```env
APP_ENV=development          # development | production
SECRET_KEY=change-this       # API key for auth (production)
APP_HOST=0.0.0.0
APP_PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./wapt.db
LOG_LEVEL=INFO
DEFAULT_RATE_LIMIT=5
DEFAULT_TIMEOUT=10
REPORT_OUTPUT_DIR=reports/output
```

---

## ⚖️ Legal & Ethics

**You are responsible for how you use this tool.**

✅ **Legal uses:**
- Testing applications you own
- Authorized client penetration tests (written contract)
- Bug bounty programs within defined scope
- Local/Docker vulnerable apps (DVWA, Juice Shop, WebGoat)
- CTF (Capture the Flag) competitions

❌ **Illegal uses:**
- Scanning any site without explicit written permission
- Using findings to harm, extort, or gain unauthorized access
- Scanning government, banking, or critical infrastructure

**Relevant laws:**
- 🇧🇩 Bangladesh: ICT Act 2006, Section 54/56
- 🇺🇸 USA: Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 UK: Computer Misuse Act 1990
- 🇪🇺 EU: Directive 2013/40/EU

The built-in scope enforcer, always-blocked domains list, and mandatory CLI confirmation are intentional safety features — do not bypass them.

---

## 🤝 Contributing

Contributions welcome. Priority areas:

1. **New vulnerability modules** — SSRF, XXE, path traversal, GraphQL
2. **New plugins** — Drop in `plugins/` following the WAPTPlugin API
3. **Payload improvements** — Better SQLi/XSS payloads in `payloads/*.yaml`
4. **Dashboard features** — Real-time WebSocket scan progress
5. **Bug fixes** — Open an issue first

```bash
# Development setup
git clone https://github.com/yourusername/wapt-framework.git
cd wapt-framework
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python cli.py server
```

---

## 📊 Project Stats

- **6 phases** built from scratch
- **15+ scanning modules** across recon, scanner, and vuln categories  
- **4 report formats** (HTML, PDF, JSON, Markdown)
- **10+ OWASP Top 10 categories** covered
- **Plugin system** with auto-discovery
- **3 stealth modes** for different engagement types
- **Full REST API** with Swagger documentation
- **React dashboard** with real-time status

---

<div align="center">

**Built with Python, FastAPI, React, and too much coffee.**

⭐ Star this repo if it helped you learn security testing

[Report Bug](../../issues) · [Request Feature](../../issues) · [Discuss](../../discussions)

---

*WAPT Framework — For authorized security testing only*

</div>
