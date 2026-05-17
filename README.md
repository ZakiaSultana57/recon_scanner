# Recon_Scanner: Automated Reconnaissance & Vulnerability Scanner

Recon_scanner is a CLI-based security assessment tool for authorized web targets. It automates reconnaissance, crawling, attack surface collection, and vulnerability scanning with built-in checks plus integrations for Nikto and Nuclei.

> Use this only on systems you own, local labs, or targets where you have explicit written permission. The scanner is rate-limited and non-destructive by design, but authorization is still mandatory.

## Features

- Accepts a domain, subdomain, URL, or IP address.
- Collects DNS data, HTTP headers, technologies, open ports, subdomains, JavaScript files, forms, parameters, and interesting endpoints.
- Recursively crawls in-scope pages with deduplication and configurable depth.
- Runs safe custom checks for missing security headers, exposed services, reflected parameters, directory listing, plaintext credential forms, and potential JavaScript secrets.
- Integrates Nikto and Nuclei when installed on the system.
- Generates JSON, Markdown, and HTML reports with severity levels and timestamps.
- Uses threaded port scanning/crawling with conservative timeouts.
- Includes a local demo target for sample scans.

## Project Structure

```text
reconx/
  cli.py          # CLI orchestration
  recon.py        # DNS, subdomain, port, header, technology recon
  crawler.py      # Recursive crawler, endpoints, JS, forms, parameters
  vuln.py         # Built-in checks plus Nikto/Nuclei wrappers
  report.py       # JSON, Markdown, HTML report generation
  target.py       # Target normalization
samples/
  test_site.py    # Local demo target for safe testing
main.py           # Entry point
Dockerfile        # Container support
requirements.txt  # Notes for dependencies
```

## Installation

Recon_Scanner core requires Python 3.9+ and uses the standard library.

```bash
python3 --version
python3 main.py --help
```

For full project requirements, install Nikto and Nuclei too.

macOS with Homebrew:

```bash
brew install nikto nuclei
nuclei -update-templates
```

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nikto
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

## Usage

Always confirm authorization:

```bash
python3 main.py https://example.com --i-have-authorization
```

Common options:

```bash
python3 main.py http://127.0.0.1:8088 \
  --i-have-authorization \
  --depth 2 \
  --max-pages 30 \
  --ports web \
  --tool-timeout 120
```

Skip external tools during quick local tests:

```bash
python3 main.py http://127.0.0.1:8088 --i-have-authorization --skip-nikto --skip-nuclei
```

Reports are saved in `reports/`:

- `*.json` for structured data.
- `*.md` for readable submission evidence.
- `*.html` for a dashboard-style report.

## Safe Local Demo

Terminal 1:

```bash
python3 samples/test_site.py --host 127.0.0.1 --port 8088
```

Terminal 2:

```bash
python3 main.py http://127.0.0.1:8088 \
  --i-have-authorization \
  --depth 2 \
  --max-pages 20 \
  --ports web \
  --skip-nikto \
  --skip-nuclei
```

The demo intentionally exposes harmless issues so your report contains findings without scanning a real third-party target.

This repository includes a verified sample report generated from that demo under `samples/reports/`.
The matching console transcript is in `samples/sample_console_output.txt`.

## Docker

Build:

```bash
docker build -t reconx .
```

Run against a permitted target:

```bash
docker run --rm -v "$PWD/reports:/app/reports" reconx https://example.com --i-have-authorization
```

## Report Contents

Each report contains:

- Target information and scan timestamp.
- DNS and subdomain findings.
- Open ports and likely services.
- HTTP headers and detected technologies.
- Crawled endpoints, parameters, forms, and JavaScript files.
- Custom, Nikto, and Nuclei vulnerability findings.
- Severity counts and remediation guidance.
 
## Ethics and Restrictions

- Scan only authorized targets.
- Do not use this tool for denial-of-service or destructive testing.
- Validate automated findings manually before reporting them.
- Keep rate limits and timeouts conservative on shared environments.

## Disclaimer

This project is developed strictly for educational purposes and authorized security testing only. The tool must only be used on systems that you own, manage, or have explicit written permission to test, such as local labs, personal virtual machines, or approved bug bounty targets.

The author is not responsible for any misuse, unauthorized scanning, service disruption, data loss, or legal consequences caused by improper use of this tool. Users are responsible for following all applicable laws, institutional policies, and ethical hacking guidelines.

ReconX is designed to perform non-destructive reconnaissance and vulnerability scanning. Findings should be manually verified before being reported or used for remediation decisions.
disruption, data loss, or legal consequences caused by improper use of this tool. Users are responsible for following all applicable laws, institutional policies, and ethical hacking guidelines.

ReconX is designed to perform non-destructive reconnaissance and vulnerability scanning. Findings should be manually verified before being reported or used for remediation decisions.
