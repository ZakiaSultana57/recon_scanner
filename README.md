Automated Reconnaissance & Vulnerability Scanner
(Project Name: ReconX – or rename as needed)

A modular CLI-based cybersecurity automation framework for passive & active reconnaissance, attack surface mapping, vulnerability scanning, and HTML report generation.

 Overview

This tool automates real-world security assessment workflows by combining:

 Passive Reconnaissance
 Active Reconnaissance
 Web Crawling & Endpoint Discovery
 Vulnerability Scanning (Nikto + Nuclei)
Structured Reporting (CLI + JSON + HTML)

It is designed for ethical hacking labs, bug bounty recon, and cybersecurity education.

 Disclaimer

This tool is strictly intended for:

✔ Authorized penetration testing
✔ Security research labs (DVWA, Juice Shop, etc.)
✔ Bug bounty programs with permission

❌ Unauthorized scanning is illegal and strictly prohibited.

🚀 Features
🔍 Reconnaissance Engine
Subdomain enumeration
DNS record extraction
WHOIS lookup
Technology fingerprinting
HTTP header analysis
Open port detection (safe mode)
JavaScript file discovery
Endpoint and directory enumeration
🧠 Crawling System
Recursive web crawling (configurable depth)
URL and parameter extraction
Form detection
JavaScript endpoint parsing
Smart deduplication & filtering
⚡ Active Recon
Lightweight port scanning
Service banner grabbing
HTTP probing
Rate-limited requests (safe-by-default)
🧪 Vulnerability Scanning

Integrated security tools:

🔹 Nikto (web server scanning)
🔹 Nuclei (template-based scanning)

Custom checks:

Missing security headers
Exposed directories
Weak HTTP methods
Misconfigurations
📊 Reporting Engine

The tool generates:

✔ CLI Report
Colored structured output
Severity-based grouping
✔ JSON Report
Machine-readable output for automation
✔ HTML Report (🔥 Hacker Theme UI)
Dark cyber UI design
Neon highlights (green/cyan/purple)
Scan timeline visualization
Vulnerability dashboard
Clickable endpoints
Severity cards (Low → Critical)
🏗️ Architecture
recon_tool/
│
├── core/              # CLI engine + config + logging
├── recon/             # passive + active recon modules
├── crawler/           # web crawler + JS analyzer
├── scanner/           # nikto + nuclei + custom checks
├── report/            # HTML + JSON report generator
├── utils/             # helpers (requests, parsing, formatting)
├── templates/         # HTML themes (hacker UI)
│
├── main.py            # entry point
├── requirements.txt
└── setup.py
⚙️ Installation
1. Clone Repository
git clone https://github.com/your-username/reconx.git
cd reconx
2. Create Virtual Environment
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
3. Install Dependencies
pip install -r requirements.txt
4. Install External Tools
Nikto
sudo apt install nikto
Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
🧑‍💻 Usage
🔹 Basic Scan
python main.py -t example.com
🔹 Full Recon + Vulnerability Scan
python main.py -t example.com --full
🔹 Recon Only Mode
python main.py -t example.com --recon
🔹 Scan Only Mode
python main.py -t example.com --scan
📤 Output Example
[+] Target: example.com
[+] Mode: Full Scan Initiated

==================== RECON ====================
Subdomains:        14 found
Technologies:      Nginx, PHP, Cloudflare
JS Files:          9 discovered
Endpoints:         52 collected

================ VULNERABILITIES ================
[HIGH] Missing Security Headers
[HIGH] XSS Vulnerability Detected
[MEDIUM] Open Directory Listing

==================== REPORT ====================
HTML Report: reports/example_com_report.html
JSON Report: reports/example_com_report.json
📊 Report Features (HTML)

The HTML report includes:

🧠 Target summary dashboard
🔍 Recon intelligence panel
🧪 Vulnerability breakdown
⚠️ Risk severity visualization
📂 Endpoint explorer
⏱️ Scan timeline
🎨 Cyberpunk hacker UI theme
🧩 Bonus Features
⚡ Multi-threaded scanning engine
🔄 Async crawling (aiohttp)
🧠 AI-powered vulnerability summarization (optional)
🐳 Docker support
🌐 Web dashboard (future upgrade)
📡 API mode (FastAPI support)
🕵️ Stealth / rate-limited scanning mode
📦 requirements.txt
requests
beautifulsoup4
lxml
colorama
tqdm
dnspython
python-nmap
jinja2
termcolor
aiohttp
🧾 setup.py
from setuptools import setup, find_packages

setup(
    name="reconx",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "lxml",
        "colorama",
        "tqdm",
        "dnspython",
        "python-nmap",
        "jinja2",
        "termcolor",
        "aiohttp"
    ],
    entry_points={
        "console_scripts": [
            "reconx = main:main"
        ]
    },
)
