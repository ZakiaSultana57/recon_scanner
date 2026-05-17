"""
ReconX - Vulnerability Scanner Module
Performs automated vulnerability scanning via:
  1. Custom checks (XSS, SQLi, open redirects, headers, misconfigs, etc.)
  2. Nikto integration
  3. Nuclei integration
"""

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import requests

from modules.logger import get_logger
from modules.utils import severity_to_int, extract_domain

logger = get_logger()

# ─── Vulnerability Finding Schema ──────────────────────────────────────────
def make_finding(
    vuln_type: str,
    url: str,
    description: str,
    severity: str = "info",
    evidence: str = "",
    remediation: str = "",
    source: str = "custom",
) -> Dict[str, Any]:
    return {
        "type":        vuln_type,
        "url":         url,
        "description": description,
        "severity":    severity.lower(),
        "evidence":    evidence[:500] if evidence else "",
        "remediation": remediation,
        "source":      source,
    }


# ─── Payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "1' AND SLEEP(3)--",
    "' UNION SELECT NULL--",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wmysqli?_",
    r"Microsoft.*Driver.*SQL",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Syntax error.*in query",
    r"sqlite3\.OperationalError",
    r"pg_query\(\):",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "/\\evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "redirect_url",
    "redirectTo", "goto", "to", "link", "redir", "destination",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
    "/database.yml", "/settings.py", "/application.properties",
    "/.aws/credentials", "/.ssh/id_rsa",
    "/backup.zip", "/backup.sql",
    "/phpinfo.php", "/server-status",
]


class VulnScannerModule:
    """
    Vulnerability scanner with custom checks, Nikto and Nuclei integration.
    """

    def __init__(
        self,
        target: str,
        urls: List[str],
        run_nikto: bool = False,
        run_nuclei: bool = False,
        run_custom: bool = True,
        min_severity: str = "info",
        threads: int = 10,
        timeout: int = 10,
    ):
        self.target = target
        self.urls = urls[:200]  # Cap for safety
        self.run_nikto = run_nikto
        self.run_nuclei = run_nuclei
        self.run_custom = run_custom
        self.min_severity = min_severity
        self.threads = threads
        self.timeout = timeout
        self.findings: List[Dict] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ReconX/1.0; security-research)"
        })
        requests.packages.urllib3.disable_warnings()

    def run(self) -> List[Dict[str, Any]]:
        """Run all enabled scanners and return deduplicated findings."""

        if self.run_custom:
            logger.info("[*] Running custom vulnerability checks...")
            self._run_custom_checks()
            logger.info(f"[+] Custom checks complete: {len(self.findings)} findings so far")

        if self.run_nikto:
            if shutil.which("nikto"):
                logger.info("[*] Running Nikto scanner...")
                nikto_findings = self._run_nikto()
                self.findings.extend(nikto_findings)
                logger.info(f"[+] Nikto: {len(nikto_findings)} findings")
            else:
                logger.warning("[!] Nikto not found in PATH. Install with: apt install nikto")

        if self.run_nuclei:
            if shutil.which("nuclei"):
                logger.info("[*] Running Nuclei scanner...")
                nuclei_findings = self._run_nuclei()
                self.findings.extend(nuclei_findings)
                logger.info(f"[+] Nuclei: {len(nuclei_findings)} findings")
            else:
                logger.warning("[!] Nuclei not found in PATH. Install from: https://nuclei.projectdiscovery.io")

        # Deduplicate and filter by severity
        seen = set()
        unique = []
        for f in self.findings:
            key = f"{f['type']}:{f['url']}"
            if key not in seen:
                seen.add(key)
                if severity_to_int(f["severity"]) >= severity_to_int(self.min_severity):
                    unique.append(f)

        # Sort by severity (highest first)
        unique.sort(key=lambda x: severity_to_int(x["severity"]), reverse=True)

        logger.info(f"[+] Total unique vulnerabilities: {len(unique)}")
        self._print_vuln_summary(unique)

        return unique

    # ──────────────────────────────────────────────────────────────
    # Custom Checks
    # ──────────────────────────────────────────────────────────────
    def _run_custom_checks(self):
        """Run all custom vulnerability checks concurrently."""
        check_fns = [
            self._check_security_headers,
            self._check_sensitive_files,
            self._check_cors_misconfig,
            self._check_clickjacking,
            self._check_open_redirect,
            self._check_information_disclosure,
        ]

        # Run header/file checks once per target
        for fn in check_fns[:4]:
            try:
                fn()
            except Exception as e:
                logger.debug(f"  Check error ({fn.__name__}): {e}")

        # Run parameter-based checks on URLs with parameters
        param_urls = [u for u in self.urls if "?" in u]
        if param_urls:
            logger.info(f"  [*] Testing {len(param_urls)} parameterized URLs...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for url in param_urls[:50]:  # Limit to 50 param URLs
                    futures.append(executor.submit(self._check_xss, url))
                    futures.append(executor.submit(self._check_sqli, url))
                    futures.append(executor.submit(self._check_open_redirect_param, url))
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.debug(f"  Param check error: {e}")

        # Check information disclosure
        self._check_information_disclosure()

    def _check_security_headers(self):
        """Check for missing security headers."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = [
                ("Strict-Transport-Security", "strict-transport-security",
                 "Missing HSTS header — allows downgrade attacks",
                 "medium", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),

                ("Content-Security-Policy", "content-security-policy",
                 "Missing Content-Security-Policy header — allows XSS via inline scripts",
                 "medium", "Implement a restrictive CSP policy"),

                ("X-Frame-Options", "x-frame-options",
                 "Missing X-Frame-Options — site may be vulnerable to clickjacking",
                 "medium", "Add X-Frame-Options: DENY or SAMEORIGIN"),

                ("X-Content-Type-Options", "x-content-type-options",
                 "Missing X-Content-Type-Options — allows MIME-type sniffing",
                 "low", "Add X-Content-Type-Options: nosniff"),

                ("Referrer-Policy", "referrer-policy",
                 "Missing Referrer-Policy — may leak sensitive URLs in Referer header",
                 "low", "Add Referrer-Policy: strict-origin-when-cross-origin"),
            ]

            for display_name, hdr_key, desc, severity, remediation in checks:
                if hdr_key not in headers:
                    self.findings.append(make_finding(
                        vuln_type=f"Missing Security Header: {display_name}",
                        url=self.target,
                        description=desc,
                        severity=severity,
                        evidence=f"Header '{display_name}' not present in response",
                        remediation=remediation,
                        source="custom",
                    ))

            # Check for server version disclosure
            server = headers.get("server", "")
            if re.search(r"\d+\.\d+", server):
                self.findings.append(make_finding(
                    vuln_type="Server Version Disclosure",
                    url=self.target,
                    description=f"Server header discloses version information: {server}",
                    severity="low",
                    evidence=f"Server: {server}",
                    remediation="Remove or obscure the Server header",
                    source="custom",
                ))

            # Check for X-Powered-By
            powered = headers.get("x-powered-by", "")
            if powered:
                self.findings.append(make_finding(
                    vuln_type="Technology Disclosure via X-Powered-By",
                    url=self.target,
                    description=f"X-Powered-By header reveals backend technology: {powered}",
                    severity="info",
                    evidence=f"X-Powered-By: {powered}",
                    remediation="Remove X-Powered-By header",
                    source="custom",
                ))

        except Exception as e:
            logger.debug(f"  Security header check error: {e}")

    def _check_sensitive_files(self):
        """Check for accessible sensitive files and directories."""
        from modules.utils import extract_base_url
        base = extract_base_url(self.target)

        def probe(path: str):
            url = base.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False, verify=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    content_snippet = resp.text[:200]
                    severity = "high"
                    if path in ("/.git/HEAD", "/.env", "/.aws/credentials"):
                        severity = "critical"
                    elif path in ("/phpinfo.php", "/server-status", "/actuator/env"):
                        severity = "high"
                    elif path in ("/robots.txt", "/sitemap.xml", "/humans.txt"):
                        severity = "info"
                        return  # Not a vulnerability

                    self.findings.append(make_finding(
                        vuln_type="Sensitive File/Directory Exposed",
                        url=url,
                        description=f"Sensitive path is publicly accessible: {path}",
                        severity=severity,
                        evidence=f"HTTP {resp.status_code}: {content_snippet}",
                        remediation=f"Restrict access to {path} via server config or remove it",
                        source="custom",
                    ))
                    logger.info(f"  [!] Sensitive file found [{resp.status_code}]: {url}")
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(probe, SENSITIVE_PATHS))

    def _check_cors_misconfig(self):
        """Check for CORS misconfiguration."""
        try:
            resp = self.session.get(
                self.target, timeout=self.timeout, verify=False,
                headers={"Origin": "https://evil.com"}
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.findings.append(make_finding(
                    vuln_type="CORS Misconfiguration: Wildcard Origin",
                    url=self.target,
                    description="Server allows requests from any origin (wildcard *)",
                    severity="medium",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict allowed origins to specific trusted domains",
                    source="custom",
                ))
            elif acao == "https://evil.com":
                severity = "critical" if acac.lower() == "true" else "high"
                self.findings.append(make_finding(
                    vuln_type="CORS Misconfiguration: Arbitrary Origin Reflection",
                    url=self.target,
                    description="Server reflects arbitrary Origin header — may allow cross-origin credential theft",
                    severity=severity,
                    evidence=f"Origin: https://evil.com → ACAO: {acao}, ACAC: {acac}",
                    remediation="Validate Origin against a whitelist before reflecting it",
                    source="custom",
                ))
        except Exception as e:
            logger.debug(f"  CORS check error: {e}")

    def _check_clickjacking(self):
        """Check for clickjacking vulnerability."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            xfo = resp.headers.get("X-Frame-Options", "").lower()
            csp = resp.headers.get("Content-Security-Policy", "")
            frame_ancestors = "frame-ancestors" in csp.lower()

            if not xfo and not frame_ancestors:
                self.findings.append(make_finding(
                    vuln_type="Clickjacking Vulnerability",
                    url=self.target,
                    description="Page can be embedded in an iframe — vulnerable to clickjacking attacks",
                    severity="medium",
                    evidence="No X-Frame-Options or CSP frame-ancestors directive found",
                    remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                    source="custom",
                ))
        except Exception:
            pass

    def _check_xss(self, url: str):
        """Test URL parameters for reflected XSS."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload in XSS_PAYLOADS[:3]:  # Limit payloads per param
                try:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)

                    if payload.lower() in resp.text.lower():
                        self.findings.append(make_finding(
                            vuln_type="Reflected Cross-Site Scripting (XSS)",
                            url=url,
                            description=f"Parameter '{param_name}' reflects user input without sanitization",
                            severity="high",
                            evidence=f"Payload reflected: {payload[:100]}",
                            remediation="Encode all user-supplied input before reflecting it in HTML responses",
                            source="custom",
                        ))
                        logger.info(f"  [!] XSS found in {url} param={param_name}")
                        return  # One finding per URL is enough

                    time.sleep(0.1)
                except Exception:
                    pass

    def _check_sqli(self, url: str):
        """Test URL parameters for SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload in SQLI_PAYLOADS[:4]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)

                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.findings.append(make_finding(
                                vuln_type="SQL Injection (Error-Based)",
                                url=url,
                                description=f"Parameter '{param_name}' may be vulnerable to SQL injection — database error detected",
                                severity="critical",
                                evidence=f"Payload: {payload} | Error pattern: {pattern}",
                                remediation="Use parameterized queries / prepared statements",
                                source="custom",
                            ))
                            logger.info(f"  [!] SQLi found in {url} param={param_name}")
                            return

                    time.sleep(0.1)
                except Exception:
                    pass

    def _check_open_redirect(self):
        """Check for open redirect on main target."""
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=self.timeout,
                                            allow_redirects=False, verify=False)
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location or payload in location:
                        self.findings.append(make_finding(
                            vuln_type="Open Redirect",
                            url=test_url,
                            description=f"Parameter '{param}' allows redirecting users to arbitrary external URLs",
                            severity="medium",
                            evidence=f"Redirect to: {location}",
                            remediation="Validate and whitelist redirect destinations",
                            source="custom",
                        ))
                        return
                except Exception:
                    pass

    def _check_open_redirect_param(self, url: str):
        """Check parameterized URL for open redirect."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in params:
            if param_name.lower() in REDIRECT_PARAMS:
                for payload in OPEN_REDIRECT_PAYLOADS[:1]:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        resp = self.session.get(test_url, timeout=self.timeout,
                                                allow_redirects=False, verify=False)
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            self.findings.append(make_finding(
                                vuln_type="Open Redirect",
                                url=url,
                                description=f"Parameter '{param_name}' redirects to arbitrary URL",
                                severity="medium",
                                evidence=f"Redirect to: {location}",
                                remediation="Validate redirect destinations against a whitelist",
                                source="custom",
                            ))
                    except Exception:
                        pass

    def _check_information_disclosure(self):
        """Check for common information disclosure issues."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            body = resp.text.lower()

            disclosures = [
                (r"stack trace|traceback|exception in thread",
                 "Stack Trace / Exception Disclosure",
                 "high", "Disable debug mode and suppress stack traces in production"),

                (r"password\s*=\s*['\"][^'\"]{4,}",
                 "Hardcoded Password in Response",
                 "critical", "Remove credentials from source code and use environment variables"),

                (r"api[_-]?key\s*[:=]\s*['\"][a-z0-9_\-]{16,}",
                 "API Key Disclosure",
                 "critical", "Remove API keys from responses and rotate exposed keys"),

                (r"-----begin (rsa |ec )?private key",
                 "Private Key Disclosure",
                 "critical", "Remove private keys immediately and rotate them"),

                (r"debug\s*=\s*true|debug_mode\s*=\s*1",
                 "Debug Mode Enabled",
                 "medium", "Disable debug mode in production"),
            ]

            for pattern, vuln_type, severity, remediation in disclosures:
                if re.search(pattern, body):
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    evidence = match.group(0)[:100] if match else ""
                    self.findings.append(make_finding(
                        vuln_type=vuln_type,
                        url=self.target,
                        description=f"Sensitive information found in page response: {vuln_type}",
                        severity=severity,
                        evidence=evidence,
                        remediation=remediation,
                        source="custom",
                    ))
                    logger.info(f"  [!] {vuln_type} detected at {self.target}")

        except Exception as e:
            logger.debug(f"  Info disclosure check error: {e}")

    # ──────────────────────────────────────────────────────────────
    # Nikto Integration
    # ──────────────────────────────────────────────────────────────
    def _run_nikto(self) -> List[Dict]:
        """Run Nikto and parse its output."""
        findings = []
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                tmp_path = tmp.name

            cmd = [
                "nikto",
                "-h", self.target,
                "-o", tmp_path,
                "-Format", "txt",
                "-nointeractive",
                "-timeout", str(self.timeout),
                "-maxtime", "300",  # 5 min max
            ]

            logger.info(f"  Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=360
            )

            with open(tmp_path, "r", errors="ignore") as f:
                output = f.read()

            os.unlink(tmp_path)

            # Parse Nikto output
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("+") and len(line) > 5:
                    # Determine severity from keywords
                    severity = "info"
                    if any(k in line.lower() for k in ["critical", "vulnerable", "cve-", "remote code"]):
                        severity = "critical"
                    elif any(k in line.lower() for k in ["high", "sql", "xss", "rce", "injection"]):
                        severity = "high"
                    elif any(k in line.lower() for k in ["medium", "directory listing", "backup"]):
                        severity = "medium"
                    elif any(k in line.lower() for k in ["low", "missing", "disclosure"]):
                        severity = "low"

                    findings.append(make_finding(
                        vuln_type="Nikto Finding",
                        url=self.target,
                        description=line.lstrip("+ "),
                        severity=severity,
                        evidence=line,
                        remediation="Review Nikto finding and apply appropriate mitigation",
                        source="nikto",
                    ))

            logger.info(f"  [+] Nikto completed with {len(findings)} findings")

        except subprocess.TimeoutExpired:
            logger.warning("[!] Nikto scan timed out")
        except FileNotFoundError:
            logger.warning("[!] Nikto executable not found")
        except Exception as e:
            logger.warning(f"[!] Nikto error: {e}")

        return findings

    # ──────────────────────────────────────────────────────────────
    # Nuclei Integration
    # ──────────────────────────────────────────────────────────────
    def _run_nuclei(self) -> List[Dict]:
        """Run Nuclei and parse its JSON output."""
        findings = []
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                tmp_path = tmp.name

            cmd = [
                "nuclei",
                "-u", self.target,
                "-o", tmp_path,
                "-json",
                "-silent",
                "-timeout", str(self.timeout),
                "-rate-limit", "50",
                "-severity", "info,low,medium,high,critical",
                "-t", "cves,vulnerabilities,exposed-panels,misconfiguration,exposures",
            ]

            logger.info(f"  Running: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            with open(tmp_path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        info = entry.get("info", {})
                        severity = info.get("severity", "info").lower()
                        name = info.get("name", "Nuclei Finding")
                        description = info.get("description", "")
                        remediation = info.get("remediation", "")
                        matched_at = entry.get("matched-at", self.target)
                        template_id = entry.get("template-id", "")
                        evidence = entry.get("extracted-results", [])
                        evidence_str = "; ".join(evidence) if evidence else template_id

                        findings.append(make_finding(
                            vuln_type=f"Nuclei: {name}",
                            url=matched_at,
                            description=description or f"Nuclei template {template_id} matched",
                            severity=severity,
                            evidence=evidence_str,
                            remediation=remediation or "Review Nuclei finding documentation",
                            source="nuclei",
                        ))
                        logger.info(f"  [!] Nuclei [{severity.upper()}]: {name} at {matched_at}")

                    except json.JSONDecodeError:
                        pass

            os.unlink(tmp_path)
            logger.info(f"  [+] Nuclei completed with {len(findings)} findings")

        except subprocess.TimeoutExpired:
            logger.warning("[!] Nuclei scan timed out")
        except FileNotFoundError:
            logger.warning("[!] Nuclei executable not found")
        except Exception as e:
            logger.warning(f"[!] Nuclei error: {e}")

        return findings

    # ──────────────────────────────────────────────────────────────
    # Summary Display
    # ──────────────────────────────────────────────────────────────
    def _print_vuln_summary(self, findings: List[Dict]):
        """Print a color-coded vulnerability summary."""
        from modules.utils import severity_color

        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        RESET = "\033[0m"
        print("\n  Vulnerability Summary:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            color = severity_color(sev)
            bar = "█" * count
            print(f"    {color}{sev.upper():10}{RESET}  {count:3d}  {color}{bar[:40]}{RESET}")
