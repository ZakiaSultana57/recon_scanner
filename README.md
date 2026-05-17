# ReconX — Automated Reconnaissance & Vulnerability Scanner

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

> **⚠ Only scan systems you are authorized to test. Unauthorized scanning is illegal.**

---

## Overview

ReconX is a modular, CLI-based automated reconnaissance and vulnerability scanning tool built for security professionals. It simulates a real-world security assessment workflow by automating the full recon-to-report pipeline.

### Key Features

| Feature | Details |
|---------|---------|
| 🌐 **Recon** | Subdomains, DNS records, open ports, HTTP headers, technology fingerprinting |
| 🕷️ **Crawling** | Recursive crawling, URL/JS/param extraction, form discovery, interesting path probing |
| 🔴 **Vuln Scanning** | Custom checks (XSS, SQLi, CORS, open redirect, misconfigs) + Nikto + Nuclei |
| 📊 **Reporting** | Dark-themed HTML report, JSON report, console summary |
| 🤖 **AI Summary** | Claude-powered executive summary (optional) |
| ⚡ **Performance** | Multi-threaded async processing, smart deduplication |
| 🐳 **Docker** | Fully containerized with Nikto + Nuclei pre-installed |

---

## Installation

### Option 1: Local (Python)

**Requirements:** Python 3.9+

```bash
# Clone the repository
git clone https://github.com/yourusername/reconx.git
cd reconx

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install Nikto
sudo apt install nikto          # Debian/Ubuntu
brew install nikto              # macOS

# (Optional) Install Nuclei
# Download from https://github.com/projectdiscovery/nuclei/releases
# Or:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Option 2: Docker (Recommended — includes Nikto + Nuclei)

```bash
# Build the image
docker build -t reconx .

# Run a scan
docker run --rm -v $(pwd)/output:/app/output reconx \
    -t http://testphp.vulnweb.com --html-report --nikto --nuclei

# With AI summary
docker run --rm \
    -e ANTHROPIC_API_KEY=your_key_here \
    -v $(pwd)/output:/app/output reconx \
    -t http://testphp.vulnweb.com --html-report --ai-summary
```

---

## Usage

```
python main.py -t <target> [options]
```

### Basic Examples

```bash
# Quick scan of a domain
python main.py -t example.com

# Full scan with HTML report
python main.py -t https://example.com --full --html-report

# Recon only (no vuln scanning)
python main.py -t example.com --recon-only

# Deep crawl with custom settings
python main.py -t example.com --depth 3 --threads 20 --delay 0.3

# Full scan with Nikto + Nuclei + AI summary
python main.py -t http://testphp.vulnweb.com --nikto --nuclei --ai-summary --html-report

# Quiet mode (no banner, minimal output)
python main.py -t example.com --quiet --html-report

# Scan IP address
python main.py -t 192.168.1.100 --full
```

### All Options

```
Target:
  -t, --target          Target domain, subdomain, URL, or IP address

Scan Modes:
  --full                Run full scan (recon + crawl + vuln scan)
  --recon-only          Run reconnaissance only
  --crawl-only          Run crawler only
  --vuln-only           Run vulnerability scan only
  --skip-vuln           Skip vulnerability scanning

Reconnaissance Options:
  --no-subdomains       Skip subdomain enumeration
  --no-ports            Skip port scanning
  --no-dns              Skip DNS enumeration
  --no-headers          Skip HTTP header analysis
  --no-tech             Skip technology detection

Crawler Options:
  --depth INT           Crawl depth (default: 2)
  --threads INT         Number of threads (default: 10)
  --timeout INT         Request timeout in seconds (default: 10)
  --delay FLOAT         Delay between requests (default: 0.5)
  --no-js               Skip JavaScript file extraction

Vulnerability Scanner Options:
  --nikto               Run Nikto scanner
  --nuclei              Run Nuclei scanner
  --custom-checks       Run custom vulnerability checks (default: on)
  --severity LEVEL      Minimum severity: info/low/medium/high/critical

Output Options:
  -o, --output DIR      Output directory (default: output/)
  --html-report         Generate HTML report
  --json-report         Generate JSON report
  --verbose, -v         Enable verbose output
  --quiet, -q           Suppress banner and progress
  --ai-summary          AI-assisted findings summary (needs ANTHROPIC_API_KEY)
```

---

## Architecture

```
reconx/
├── main.py                  # CLI entry point
├── modules/
│   ├── banner.py            # ASCII banner
│   ├── logger.py            # Colored logging
│   ├── utils.py             # Shared utilities
│   ├── recon.py             # Reconnaissance module
│   │   ├── DNS enumeration
│   │   ├── Subdomain brute-force
│   │   ├── Port scanning
│   │   ├── HTTP header analysis
│   │   └── Technology detection
│   ├── crawler.py           # Web crawler module
│   │   ├── Recursive BFS crawling
│   │   ├── URL/parameter extraction
│   │   ├── Form discovery
│   │   ├── JS file analysis
│   │   └── Interesting path probing
│   ├── vuln_scanner.py      # Vulnerability scanner
│   │   ├── Custom checks (XSS, SQLi, CORS, headers...)
│   │   ├── Nikto integration
│   │   └── Nuclei integration
│   └── reporter.py          # Report generation
│       ├── HTML report (dark-themed)
│       ├── JSON report
│       ├── Console summary
│       └── AI summary (optional)
├── output/                  # Generated reports
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## Custom Vulnerability Checks

ReconX includes the following built-in checks (no external tools needed):

| Check | Severity | Description |
|-------|----------|-------------|
| Missing Security Headers | Low–Medium | HSTS, CSP, X-Frame-Options, etc. |
| CORS Misconfiguration | Medium–Critical | Wildcard origin, reflected origin with credentials |
| Clickjacking | Medium | No X-Frame-Options or CSP frame-ancestors |
| Reflected XSS | High | Parameter injection with reflection detection |
| SQL Injection (Error-Based) | Critical | Error pattern matching |
| Open Redirect | Medium | Redirect parameter abuse |
| Sensitive File Exposure | High–Critical | .env, .git, config files, backups |
| Server Version Disclosure | Low | Version info in Server header |
| Technology Disclosure | Info | X-Powered-By header |
| Stack Trace Disclosure | High | Exception/traceback in responses |
| API Key / Credential Disclosure | Critical | Regex-based secret detection |
| Debug Mode Enabled | Medium | debug=true in responses |

---

## Nikto Integration

Automatically invoked with `--nikto`. Parses Nikto text output and maps to ReconX severity levels.

```bash
python main.py -t http://target.com --nikto
```

Requires `nikto` in PATH:
```bash
sudo apt install nikto
```

---

## Nuclei Integration

Automatically invoked with `--nuclei`. Parses Nuclei JSON output and imports findings with full metadata.

```bash
python main.py -t http://target.com --nuclei
```

Requires `nuclei` in PATH:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## AI-Assisted Summary

Pass `--ai-summary` with `ANTHROPIC_API_KEY` set to generate an executive summary:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python main.py -t http://target.com --ai-summary --html-report
```

The summary includes:
- Executive overview of the security posture
- Top critical findings with explanations
- Prioritized remediation steps
- Overall risk rating

---

## Output Files

All reports are saved to the `output/` directory (or `-o` path):

```
output/
├── reconx_http_example_com_20241215_143022.html    # HTML report
└── reconx_http_example_com_20241215_143022.json    # JSON report
```

The HTML report features:
- Dark-themed responsive design
- Interactive severity filter buttons
- Sections: Overview, Vulnerabilities, Recon, Crawl Results, Security Headers
- Collapsible URL lists and evidence
- Print-friendly layout

---

## Authorized Test Targets

Use these **legal** targets for testing ReconX:

| Target | Description |
|--------|-------------|
| `http://testphp.vulnweb.com` | Acunetix deliberately vulnerable PHP app |
| `http://testfire.net` | IBM AltoroMutual demo banking app |
| `http://demo.testfire.net` | IBM Altoro Mutual |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop |
| Your local VMs | Metasploitable, DVWA, VulnHub VMs |
| HackTheBox / TryHackMe VPNs | With active lab machines |

---

## Legal & Ethical Notice

> **This tool is for authorized security testing only.**
>
> - Only scan systems you own or have explicit written permission to test.
> - Do not use on production systems without authorization.
> - Respect rate limits and avoid denial-of-service conditions.
> - Follow all applicable laws (CFAA, Computer Misuse Act, etc.).
> - The authors assume no liability for misuse.

---

## Sample Report

A sample scan report against `http://testphp.vulnweb.com` is included in `sample_output/`.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
