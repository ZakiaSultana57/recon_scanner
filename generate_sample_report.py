#!/usr/bin/env python3
"""
Generate a realistic sample report for demonstration purposes.
This simulates the output of scanning http://testphp.vulnweb.com
"""

import json
import os
import sys

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.reporter import ReportGenerator

SAMPLE_RESULTS = {
    "target": "http://testphp.vulnweb.com",
    "original_input": "testphp.vulnweb.com",
    "scan_start": "2025-03-15T14:30:22.000000",
    "scan_end":   "2025-03-15T14:47:55.000000",
    "scan_duration": "0:17:33",
    "recon": {
        "domain": "testphp.vulnweb.com",
        "ip": "44.228.249.3",
        "subdomains": [
            {"subdomain": "www.vulnweb.com",    "ip": "44.228.249.3"},
            {"subdomain": "admin.vulnweb.com",  "ip": "44.228.249.3"},
            {"subdomain": "mail.vulnweb.com",   "ip": "44.228.249.3"},
            {"subdomain": "ftp.vulnweb.com",    "ip": "44.228.249.3"},
        ],
        "dns": {
            "A":   ["44.228.249.3"],
            "MX":  ["10 mail.vulnweb.com."],
            "NS":  ["ns1.vulnweb.com.", "ns2.vulnweb.com."],
            "TXT": ["v=spf1 include:_spf.vulnweb.com ~all"],
        },
        "open_ports": [
            {"port": 22,  "service": "SSH",   "banner": "SSH-2.0-OpenSSH_7.4", "state": "open"},
            {"port": 80,  "service": "HTTP",  "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7", "state": "open"},
            {"port": 443, "service": "HTTPS", "banner": "", "state": "open"},
            {"port": 3306,"service": "MySQL", "banner": "", "state": "open"},
        ],
        "http_headers": {
            "Server": "Apache/2.4.7 (Ubuntu)",
            "X-Powered-By": "PHP/5.6.40",
            "Content-Type": "text/html; charset=UTF-8",
            "Connection": "keep-alive",
        },
        "security_headers": {
            "X-Content-Type-Options": "nosniff",
        },
        "missing_security_headers": [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
        ],
        "technologies": [
            "Apache HTTP Server",
            "PHP",
            "jQuery",
            "Bootstrap",
        ],
    },
    "crawl": {
        "urls": [
            "http://testphp.vulnweb.com/",
            "http://testphp.vulnweb.com/index.php",
            "http://testphp.vulnweb.com/login.php",
            "http://testphp.vulnweb.com/signup.php",
            "http://testphp.vulnweb.com/cart.php",
            "http://testphp.vulnweb.com/search.php?test=query",
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "http://testphp.vulnweb.com/listproducts.php?cat=2",
            "http://testphp.vulnweb.com/artists.php",
            "http://testphp.vulnweb.com/artist.php?artist=1",
            "http://testphp.vulnweb.com/guestbook.php",
            "http://testphp.vulnweb.com/userinfo.php",
            "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg",
            "http://testphp.vulnweb.com/hpp/?pp=12",
            "http://testphp.vulnweb.com/admin/",
            "http://testphp.vulnweb.com/categories.php",
        ],
        "js_files": [
            "http://testphp.vulnweb.com/js/jquery-1.7.min.js",
            "http://testphp.vulnweb.com/js/bootstrap.min.js",
            "http://testphp.vulnweb.com/js/validate.js",
        ],
        "parameters": {
            "http://testphp.vulnweb.com/search.php?test=query": ["test"],
            "http://testphp.vulnweb.com/listproducts.php?cat=1": ["cat"],
            "http://testphp.vulnweb.com/artist.php?artist=1": ["artist"],
            "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg": ["file"],
            "http://testphp.vulnweb.com/hpp/?pp=12": ["pp"],
        },
        "forms": [
            {"url": "http://testphp.vulnweb.com/login.php",  "method": "POST",
             "inputs": {"uname": "text", "pass": "password", "submit": "submit"}},
            {"url": "http://testphp.vulnweb.com/search.php", "method": "GET",
             "inputs": {"searchFor": "text", "goButton": "submit"}},
            {"url": "http://testphp.vulnweb.com/guestbook.php", "method": "POST",
             "inputs": {"name": "text", "text": "textarea", "submit": "submit"}},
        ],
        "interesting_paths": [
            {"url": "http://testphp.vulnweb.com/admin/",      "status_code": 200, "path": "/admin/",      "interesting": True},
            {"url": "http://testphp.vulnweb.com/phpinfo.php", "status_code": 200, "path": "/phpinfo.php", "interesting": True},
            {"url": "http://testphp.vulnweb.com/.git/HEAD",   "status_code": 200, "path": "/.git/HEAD",   "interesting": True},
            {"url": "http://testphp.vulnweb.com/robots.txt",  "status_code": 200, "path": "/robots.txt",  "interesting": True},
        ],
        "api_endpoints": [],
        "emails": ["admin@vulnweb.com", "support@vulnweb.com"],
        "total_urls": 16,
    },
    "vulnerabilities": [
        {
            "type": "SQL Injection (Error-Based)",
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "description": "Parameter 'cat' may be vulnerable to SQL injection — database error detected",
            "severity": "critical",
            "evidence": "Payload: ' | Error pattern: sql syntax",
            "remediation": "Use parameterized queries / prepared statements",
            "source": "custom",
        },
        {
            "type": "SQL Injection (Error-Based)",
            "url": "http://testphp.vulnweb.com/artist.php?artist=1",
            "description": "Parameter 'artist' may be vulnerable to SQL injection — database error detected",
            "severity": "critical",
            "evidence": "Payload: ' OR '1'='1 | Error pattern: mysql_fetch",
            "remediation": "Use parameterized queries / prepared statements",
            "source": "custom",
        },
        {
            "type": "Sensitive File/Directory Exposed",
            "url": "http://testphp.vulnweb.com/.git/HEAD",
            "description": "Sensitive path is publicly accessible: /.git/HEAD",
            "severity": "critical",
            "evidence": "HTTP 200: ref: refs/heads/master",
            "remediation": "Block access to .git directory via server config",
            "source": "custom",
        },
        {
            "type": "Reflected Cross-Site Scripting (XSS)",
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "description": "Parameter 'test' reflects user input without sanitization",
            "severity": "high",
            "evidence": "Payload reflected: <script>alert(1)</script>",
            "remediation": "Encode all user-supplied input before reflecting it in HTML responses",
            "source": "custom",
        },
        {
            "type": "Sensitive File/Directory Exposed",
            "url": "http://testphp.vulnweb.com/phpinfo.php",
            "description": "Sensitive path is publicly accessible: /phpinfo.php",
            "severity": "high",
            "evidence": "HTTP 200: PHP Version 5.6.40 | Server configuration details exposed",
            "remediation": "Remove phpinfo.php from production servers",
            "source": "custom",
        },
        {
            "type": "Reflected Cross-Site Scripting (XSS)",
            "url": "http://testphp.vulnweb.com/guestbook.php",
            "description": "Parameter 'name' reflects user input without sanitization (Stored XSS risk)",
            "severity": "high",
            "evidence": 'Payload reflected: "><svg onload=alert(1)>',
            "remediation": "Sanitize and encode all user input stored and reflected in HTML",
            "source": "custom",
        },
        {
            "type": "CORS Misconfiguration: Wildcard Origin",
            "url": "http://testphp.vulnweb.com",
            "description": "Server allows requests from any origin (wildcard *)",
            "severity": "medium",
            "evidence": "Access-Control-Allow-Origin: *",
            "remediation": "Restrict allowed origins to specific trusted domains",
            "source": "custom",
        },
        {
            "type": "Missing Security Header: Content-Security-Policy",
            "url": "http://testphp.vulnweb.com",
            "description": "Missing Content-Security-Policy header — allows XSS via inline scripts",
            "severity": "medium",
            "evidence": "Header 'Content-Security-Policy' not present in response",
            "remediation": "Implement a restrictive CSP policy",
            "source": "custom",
        },
        {
            "type": "Missing Security Header: Strict-Transport-Security",
            "url": "http://testphp.vulnweb.com",
            "description": "Missing HSTS header — allows downgrade attacks",
            "severity": "medium",
            "evidence": "Header 'Strict-Transport-Security' not present in response",
            "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "source": "custom",
        },
        {
            "type": "Clickjacking Vulnerability",
            "url": "http://testphp.vulnweb.com",
            "description": "Page can be embedded in an iframe — vulnerable to clickjacking attacks",
            "severity": "medium",
            "evidence": "No X-Frame-Options or CSP frame-ancestors directive found",
            "remediation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
            "source": "custom",
        },
        {
            "type": "Missing Security Header: X-Frame-Options",
            "url": "http://testphp.vulnweb.com",
            "description": "Missing X-Frame-Options — site may be vulnerable to clickjacking",
            "severity": "medium",
            "evidence": "Header 'X-Frame-Options' not present in response",
            "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
            "source": "custom",
        },
        {
            "type": "Server Version Disclosure",
            "url": "http://testphp.vulnweb.com",
            "description": "Server header discloses version information: Apache/2.4.7 (Ubuntu)",
            "severity": "low",
            "evidence": "Server: Apache/2.4.7 (Ubuntu)",
            "remediation": "Remove or obscure the Server header via ServerTokens Prod",
            "source": "custom",
        },
        {
            "type": "Missing Security Header: X-Content-Type-Options",
            "url": "http://testphp.vulnweb.com",
            "description": "Missing X-Content-Type-Options — allows MIME-type sniffing",
            "severity": "low",
            "evidence": "Header 'X-Content-Type-Options' not present in response",
            "remediation": "Add X-Content-Type-Options: nosniff",
            "source": "custom",
        },
        {
            "type": "Technology Disclosure via X-Powered-By",
            "url": "http://testphp.vulnweb.com",
            "description": "X-Powered-By header reveals backend technology: PHP/5.6.40",
            "severity": "info",
            "evidence": "X-Powered-By: PHP/5.6.40",
            "remediation": "Remove X-Powered-By header via php.ini expose_php = Off",
            "source": "custom",
        },
        {
            "type": "Nikto Finding",
            "url": "http://testphp.vulnweb.com",
            "description": "Server leaks inodes via ETags, header found with file /",
            "severity": "low",
            "evidence": "+ Server leaks inodes via ETags, header found with file /",
            "remediation": "Disable ETag header or configure to not include inode information",
            "source": "nikto",
        },
        {
            "type": "Nikto Finding",
            "url": "http://testphp.vulnweb.com",
            "description": "The anti-clickjacking X-Frame-Options header is not present",
            "severity": "medium",
            "evidence": "+ The anti-clickjacking X-Frame-Options header is not present",
            "remediation": "Add X-Frame-Options header",
            "source": "nikto",
        },
    ],
}

if __name__ == "__main__":
    os.makedirs("sample_output", exist_ok=True)
    
    reporter = ReportGenerator(
        results=SAMPLE_RESULTS,
        output_dir="sample_output",
        target="http://testphp.vulnweb.com",
        ai_summary=False,
    )

    json_path = reporter.generate_json()
    print(f"[+] JSON report: {json_path}")

    html_path = reporter.generate_html()
    print(f"[+] HTML report: {html_path}")

    reporter.print_summary()
    print("[*] Sample reports generated in sample_output/")
