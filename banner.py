"""
ReconX - Reconnaissance Module
Performs automated information gathering:
  - Subdomain enumeration
  - DNS records
  - Open port scanning
  - HTTP header analysis
  - Technology/framework detection
  - WHOIS-style info
"""

import concurrent.futures
import json
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import dns.resolver
import dns.exception

from modules.logger import get_logger
from modules.utils import extract_domain, resolve_ip

logger = get_logger()

# Common subdomain wordlist (built-in, no file needed)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "api", "app", "dev", "staging", "test", "beta", "admin",
    "portal", "login", "secure", "static", "cdn", "media", "img",
    "images", "upload", "download", "files", "docs", "support",
    "help", "status", "monitor", "dashboard", "blog", "shop", "store",
    "forum", "wiki", "m", "mobile", "wap", "ns1", "ns2", "ns3",
    "mx", "mx1", "mx2", "relay", "gateway", "proxy", "ldap",
    "intranet", "extranet", "internal", "external", "old", "new",
    "v1", "v2", "v3", "backup", "db", "database", "sql", "mysql",
    "redis", "elastic", "kibana", "grafana", "jenkins", "git", "gitlab",
    "github", "jira", "confluence", "auth", "sso", "oauth", "pay",
    "payment", "billing", "invoice", "crm", "erp", "hr", "uat",
    "qa", "sandbox", "demo", "preview", "review",
]

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
                6379, 8080, 8081, 8443, 8888, 9200, 9300, 27017]

# Technology fingerprints: (header/body pattern -> tech name)
TECH_FINGERPRINTS = {
    # Server headers
    "server_headers": {
        "apache":     "Apache HTTP Server",
        "nginx":      "Nginx",
        "iis":        "Microsoft IIS",
        "litespeed":  "LiteSpeed",
        "cloudflare": "Cloudflare",
        "openresty":  "OpenResty",
        "gunicorn":   "Gunicorn",
        "uvicorn":    "Uvicorn",
        "tomcat":     "Apache Tomcat",
        "jetty":      "Jetty",
    },
    # X-Powered-By header
    "powered_by": {
        "php":            "PHP",
        "asp.net":        "ASP.NET",
        "express":        "Express.js",
        "next.js":        "Next.js",
        "django":         "Django",
        "ruby on rails":  "Ruby on Rails",
        "laravel":        "Laravel",
        "wordpress":      "WordPress",
    },
    # HTML body patterns
    "body_patterns": {
        r"wp-content|wp-includes":          "WordPress",
        r"joomla":                           "Joomla",
        r"drupal":                           "Drupal",
        r"<meta[^>]+generator[^>]+laravel": "Laravel",
        r"react\.production\.min\.js|__REACT": "React",
        r"angular\.min\.js|ng-version":     "Angular",
        r"vue\.min\.js|__VUE__":            "Vue.js",
        r"jquery[\.\-][\d\.]+\.min\.js":    "jQuery",
        r"bootstrap\.min\.css|bootstrap\.bundle": "Bootstrap",
        r"tailwindcss":                      "Tailwind CSS",
        r"__next|_next/static":             "Next.js",
        r"nuxt":                             "Nuxt.js",
        r"shopify":                          "Shopify",
        r"wix\.com":                         "Wix",
        r"squarespace":                      "Squarespace",
        r"ghost\.io|ghost-theme":            "Ghost CMS",
    },
    # Cookie names
    "cookies": {
        "PHPSESSID":       "PHP",
        "JSESSIONID":      "Java (Servlet)",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "wp-settings":     "WordPress",
        "django":          "Django",
    },
}

# Interesting HTTP security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
]


class ReconModule:
    """
    Handles all reconnaissance tasks for a given target.
    """

    def __init__(
        self,
        target: str,
        skip_subdomains: bool = False,
        skip_ports: bool = False,
        skip_dns: bool = False,
        skip_headers: bool = False,
        skip_tech: bool = False,
        threads: int = 10,
        timeout: int = 10,
    ):
        self.target = target
        self.domain = extract_domain(target)
        self.skip_subdomains = skip_subdomains
        self.skip_ports = skip_ports
        self.skip_dns = skip_dns
        self.skip_headers = skip_headers
        self.skip_tech = skip_tech
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ReconX/1.0; security-research)"
        })

    def run(self) -> Dict[str, Any]:
        """Execute all recon tasks and return aggregated results."""
        results: Dict[str, Any] = {
            "domain":      self.domain,
            "ip":          None,
            "subdomains":  [],
            "dns":         {},
            "open_ports":  [],
            "http_headers": {},
            "security_headers": {},
            "missing_security_headers": [],
            "technologies": [],
            "whois_info":  {},
        }

        # Resolve IP
        ip = resolve_ip(self.domain)
        results["ip"] = ip
        if ip:
            logger.info(f"[+] Resolved {self.domain} → {ip}")
        else:
            logger.warning(f"[!] Could not resolve IP for {self.domain}")

        # DNS records
        if not self.skip_dns:
            logger.info("[*] Enumerating DNS records...")
            results["dns"] = self._get_dns_records()

        # Subdomain enumeration
        if not self.skip_subdomains:
            logger.info("[*] Enumerating subdomains...")
            results["subdomains"] = self._enumerate_subdomains()
            logger.info(f"[+] Found {len(results['subdomains'])} subdomains")

        # Port scanning
        if not self.skip_ports and ip:
            logger.info("[*] Scanning common ports...")
            results["open_ports"] = self._scan_ports(ip)
            logger.info(f"[+] Found {len(results['open_ports'])} open ports")

        # HTTP headers
        if not self.skip_headers:
            logger.info("[*] Analyzing HTTP headers...")
            headers_data = self._analyze_headers()
            results["http_headers"]  = headers_data.get("headers", {})
            results["security_headers"] = headers_data.get("security", {})
            results["missing_security_headers"] = headers_data.get("missing", [])

        # Technology detection
        if not self.skip_tech:
            logger.info("[*] Detecting technologies...")
            results["technologies"] = self._detect_technologies(
                results.get("http_headers", {})
            )
            if results["technologies"]:
                logger.info(f"[+] Detected: {', '.join(results['technologies'])}")

        return results

    # ──────────────────────────────────────────────────────────────
    # DNS Enumeration
    # ──────────────────────────────────────────────────────────────
    def _get_dns_records(self) -> Dict[str, List[str]]:
        """Fetch A, AAAA, MX, NS, TXT, CNAME, SOA records."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        dns_data: Dict[str, List[str]] = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(self.domain, rtype)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                if records:
                    dns_data[rtype] = records
                    logger.debug(f"  DNS {rtype}: {records}")
            except (dns.exception.DNSException, Exception):
                pass

        return dns_data

    # ──────────────────────────────────────────────────────────────
    # Subdomain Enumeration
    # ──────────────────────────────────────────────────────────────
    def _enumerate_subdomains(self) -> List[Dict[str, str]]:
        """
        Enumerate subdomains via DNS brute-force.
        Returns list of {subdomain, ip} dicts.
        """
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        def check_subdomain(prefix: str):
            fqdn = f"{prefix}.{self.domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ip = str(answers[0])
                return {"subdomain": fqdn, "ip": ip}
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in SUBDOMAIN_WORDLIST}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    logger.info(f"  [+] Subdomain: {result['subdomain']} ({result['ip']})")

        return found

    # ──────────────────────────────────────────────────────────────
    # Port Scanning
    # ──────────────────────────────────────────────────────────────
    def _scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        """Scan common ports and grab banners where possible."""
        open_ports = []

        def check_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = ""
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    sock.close()
                    return {
                        "port":    port,
                        "service": _port_to_service(port),
                        "banner":  banner[:200] if banner else "",
                        "state":   "open",
                    }
                sock.close()
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads * 2, 50)) as executor:
            futures = [executor.submit(check_port, port) for port in COMMON_PORTS]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.info(f"  [+] Open port: {result['port']}/tcp ({result['service']})")

        return sorted(open_ports, key=lambda x: x["port"])

    # ──────────────────────────────────────────────────────────────
    # HTTP Header Analysis
    # ──────────────────────────────────────────────────────────────
    def _analyze_headers(self) -> Dict[str, Any]:
        """Fetch and analyze HTTP response headers."""
        try:
            resp = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            headers = dict(resp.headers)

            # Check security headers
            present_security = {}
            missing = []
            for hdr in SECURITY_HEADERS:
                val = headers.get(hdr) or headers.get(hdr.lower())
                if val:
                    present_security[hdr] = val
                    logger.debug(f"  Header {hdr}: {val[:80]}")
                else:
                    missing.append(hdr)
                    logger.debug(f"  [!] Missing security header: {hdr}")

            if missing:
                logger.info(f"  [!] Missing {len(missing)} security headers: {', '.join(missing)}")

            return {
                "headers":  headers,
                "security": present_security,
                "missing":  missing,
                "status_code": resp.status_code,
            }
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                import urllib3
                urllib3.disable_warnings()
                resp = self.session.get(self.target, timeout=self.timeout,
                                        allow_redirects=True, verify=False)
                return {"headers": dict(resp.headers), "security": {}, "missing": SECURITY_HEADERS}
            except Exception as e:
                logger.warning(f"[!] Could not fetch headers: {e}")
                return {"headers": {}, "security": {}, "missing": SECURITY_HEADERS}
        except Exception as e:
            logger.warning(f"[!] Could not fetch headers: {e}")
            return {"headers": {}, "security": {}, "missing": SECURITY_HEADERS}

    # ──────────────────────────────────────────────────────────────
    # Technology Detection
    # ──────────────────────────────────────────────────────────────
    def _detect_technologies(self, headers: Dict[str, str]) -> List[str]:
        """Detect technologies from headers and page body."""
        detected = set()

        # Check Server header
        server = headers.get("Server", headers.get("server", "")).lower()
        for sig, tech in TECH_FINGERPRINTS["server_headers"].items():
            if sig in server:
                detected.add(tech)

        # Check X-Powered-By
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", "")).lower()
        for sig, tech in TECH_FINGERPRINTS["powered_by"].items():
            if sig in powered:
                detected.add(tech)

        # Check Set-Cookie header
        cookies_hdr = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        for cookie_name, tech in TECH_FINGERPRINTS["cookies"].items():
            if cookie_name in cookies_hdr:
                detected.add(tech)

        # Fetch body and check patterns
        try:
            import urllib3
            urllib3.disable_warnings()
            resp = self.session.get(self.target, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
            body = resp.text[:50000]  # First 50KB is enough
            for pattern, tech in TECH_FINGERPRINTS["body_patterns"].items():
                if re.search(pattern, body, re.IGNORECASE):
                    detected.add(tech)
        except Exception:
            pass

        return sorted(detected)


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────
def _port_to_service(port: int) -> str:
    """Return common service name for a port number."""
    services = {
        21: "FTP",    22: "SSH",     23: "Telnet",  25: "SMTP",
        53: "DNS",    80: "HTTP",   110: "POP3",   111: "RPC",
       135: "MSRPC", 139: "NetBIOS",143: "IMAP",  443: "HTTPS",
       445: "SMB",   993: "IMAPS",  995: "POP3S", 1723: "PPTP",
      3306: "MySQL", 3389: "RDP",  5432: "PostgreSQL",
      5900: "VNC",   6379: "Redis", 8080: "HTTP-Alt",
      8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
      9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
     27017: "MongoDB",
    }
    return services.get(port, "unknown")
