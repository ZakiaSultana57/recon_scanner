# Recon_Scanner:Automated Reconnaissance & Vulnerability Scanner

A lightweight CLI-based tool that automates reconnaissance and vulnerability scanning for web targets. This project simulates a real-world security assessment workflow by combining information gathering, crawling, data extraction, and vulnerability scanning.

# **Features**
- Accepts domain, URL, or IP as input
- Performs automated reconnaissance
- Recursive web crawling
- Endpoint and URL collection
- Parameter extraction
- JavaScript file discovery
- Integration with Nikto and Nuclei
- Structured JSON report generation
- Clean CLI output
- Project Structure


  
scanner/
main.py            
recon.py          
crawler.py         
extractor.py       
vulnscan.py        
report.py          
output/            



# **Installation**
 

1️ Clone Repository
git clone https://github.com/ZakiaSultana57/recon_scanner.git
cd recon-scanner



2️ Install Python Dependencies
pip install requests beautifulsoup4



3️ Install Required Tools



Make sure the following tools are installed and available in your system:

nmap
nikto
nuclei
curl



Ubuntu/Debian:
sudo apt update
sudo apt install nmap nikto curl



Install Nuclei:
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


# Usage

python main.py -t http://example.com


Sample Output
[+] Starting scan...
[+] Running Recon...
[+] Crawling target...
[+] Extracting data...
[+] Running vulnerability scans...
[+] Report saved: output/report_2026-05-18_12-30-22.json



📄 Sample Report Structure


# Ethical Usage:
 
Important: This tool is intended for educational purposes only.

1.Scan only authorized targets (e.g., local labs, test environments, bug bounty programs)
2.Do NOT perform unauthorized scanning
3.Do NOT attempt exploitation or data destruction
4.Do NOT perform Denial-of-Service (DoS) attacks



# **Conclusion**

This project demonstrates a practical implementation of automated reconnaissance and vulnerability scanning using real-world tools and techniques. It provides a strong foundation for further development into a full-featured security assessment framework.
Recon_scanner is designed to perform non-destructive reconnaissance and vulnerability scanning. Findings should be manually verified before being reported or used for remediation decisions.
disruption, data loss, or legal consequences caused by improper use of this tool. Users are responsible for following all applicable laws, institutional policies, and ethical hacking guidelines.

