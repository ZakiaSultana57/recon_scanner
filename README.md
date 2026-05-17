 Recon_scanner: Automated Reconnaissance & Vulnerability Scanner
📌 Project Overview

The Automated Reconnaissance & Vulnerability Scanner is a CLI-based security tool designed to simulate a real-world web application security assessment workflow. It automates both passive and active reconnaissance, discovers attack surface information, and performs vulnerability scanning using integrated security tools.

The tool is intended for educational and authorized security testing purposes only.

🎯 Objectives
Automate reconnaissance of web targets (domain, subdomain, URL, or IP).
Identify and map attack surface components.
Perform crawling and endpoint discovery.
Extract parameters, JavaScript files, and hidden assets.
Detect common web vulnerabilities using automated scanners.
Generate structured and readable security reports.
⚙️ Features
🔍 Reconnaissance (Passive & Active)
Subdomain enumeration
DNS information gathering
Open port and service detection
HTTP header analysis
Technology stack detection
JavaScript file discovery
Endpoint and directory enumeration
Parameter and form extraction
🧪 Vulnerability Scanning
Integration with Nikto for web server scanning
Integration with Nuclei for template-based vulnerability detection
Custom vulnerability checks (extendable module)
Severity classification of findings
🌐 Crawling & Analysis
URL crawling and endpoint collection
Recursive crawling support (optional feature)
Smart filtering and deduplication of results
JavaScript parsing for hidden endpoints and APIs
📊 Reporting
Structured scan report generation
Summary of reconnaissance data
Detailed vulnerability findings
Severity tagging (Low / Medium / High / Critical)
Timestamped scan results
Exportable report format (CLI / file-based output)
🏗️ Architecture

The tool follows a modular architecture for scalability and maintainability:

project/
│
├── recon/               # Reconnaissance modules
├── scanner/             # Vulnerability scanning modules
├── crawler/             # URL crawling engine
├── utils/               # Helper functions (logging, parsing, etc.)
├── report/              # Report generation
├── config/              # Configuration files
└── main.py              # CLI entry point
🚀 Installation
1. Clone the Repository
git clone https://github.com/your-username/recon-scanner.git
cd recon-scanner
2. Create Virtual Environment (Recommended)
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
3. Install Dependencies
pip install -r requirements.txt
4. Install External Tools

Ensure the following tools are installed and available in PATH:

Nikto
Nuclei

Example:

sudo apt install nikto
GO install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
🧑‍💻 Usage
Basic Scan
python main.py -t example.com
Scan with Full Recon + Vulnerability Assessment
python main.py -t https://example.com --full-scan
Scan IP Address
python main.py -t 192.168.1.1
Enable Verbose Mode
python main.py -t example.com -v
📤 Output Example
[+] Target: example.com
[+] Scan Started: 2026-05-17 10:30:00

[RECONNAISSANCE]
- Subdomains Found: 5
- Open Ports: 80, 443
- Technologies: Nginx, PHP, Cloudflare
- JS Files: 12 discovered
- Endpoints: 45 collected

[VULNERABILITIES]
- SQL Injection (High)
- Missing Security Headers (Medium)
- XSS Reflected (High)

[REPORT]
Report saved to: reports/example_com_17052026.json
📊 Report Structure

The final report includes:

Target Information
Reconnaissance Data
Crawled URLs & Endpoints
Extracted Parameters
JavaScript File Analysis
Vulnerability Findings
Risk Levels
Scan Timestamp
🧩 Bonus Features (Optional Enhancements)
🔁 Recursive crawling engine
⚡ Multi-threaded scanning for performance
🧠 AI-based summary of vulnerabilities
🌐 Web-based dashboard (Flask / FastAPI)
📄 HTML/PDF report export
🐳 Docker containerization
🕵️ Stealth scanning (rate limiting & delay control)
📊 Visual analytics dashboard
⚠️ Ethical & Legal Disclaimer

This tool is developed strictly for educational purposes and authorized security testing only.

❗ Important Rules:
Do NOT scan systems without explicit permission.
Use only on:
Your own systems
Local virtual labs (DVWA, Juice Shop, etc.)
Authorized bug bounty programs
The developer assumes no responsibility for misuse of this tool.
🛠️ Technologies Used
Python 3.x
Requests / HTTP libraries
Subprocess automation
BeautifulSoup / Scrapy (for crawling)
Nikto (vulnerability scanning)
Nuclei (template-based scanning)
📅 Project Status

🚧 In Development — Core features under active implementation

👨‍💻 Author
Name: Your Name
GitHub: https://github.com/your-username
📜 License

This project is licensed under the MIT License.
