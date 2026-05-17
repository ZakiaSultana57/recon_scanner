"""
ReconX - Crawler Module
Performs recursive web crawling to discover:
  - URLs and endpoints
  - Parameters (GET/POST/forms)
  - JavaScript files
  - Interesting paths / admin panels
  - API endpoints
"""

import concurrent.futures
import json
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

from modules.logger import get_logger
from modules.utils import (
    extract_domain, is_same_domain, normalize_url, extract_base_url
)

logger = get_logger()

# Paths to always try discovering
INTERESTING_PATHS = [
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/login", "/signin", "/register", "/signup",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql",
    "/.env", "/.git/HEAD", "/.git/config", "/.svn",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/wp-admin", "/wp-login.php", "/wp-config.php.bak",
    "/phpinfo.php", "/info.php", "/test.php",
    "/config", "/config.php", "/configuration.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql",
    "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/humans.txt", "/README.md", "/CHANGELOG.md",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/redoc", "/docs",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/health", "/status", "/ping",
    "/console", "/manager", "/jmx-console",
    "/phpmyadmin", "/pma", "/dbadmin",
    "/cgi-bin/", "/cgi-bin/test-cgi", "/cgi-bin/printenv",
    "/server-status", "/server-info",
    "/.DS_Store", "/Thumbs.db",
]

JS_URL_PATTERN = re.compile(
    r'(?:url|href|src|action|endpoint|path|route|api)["\s]*[:=]["\s]*'
    r'["\']([/a-zA-Z0-9_\-\.?&=#+%@:]+)["\']',
    re.IGNORECASE
)

API_PATTERN = re.compile(
    r'(?:/api/|/v\d+/|/rest/|/graphql)[a-zA-Z0-9/_\-\.]*',
    re.IGNORECASE
)


class CrawlerModule:
    """
    Recursive web crawler with asset discovery and deduplication.
    """

    def __init__(
        self,
        target: str,
        depth: int = 2,
        threads: int = 10,
        timeout: int = 10,
        delay: float = 0.5,
        extract_js: bool = True,
    ):
        self.target = target
        self.base_domain = extract_domain(target)
        self.base_url = extract_base_url(target)
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.extract_js = extract_js

        self.visited: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}  # url -> set of param names
        self.forms: List[Dict] = []
        self.interesting_found: List[Dict] = []
        self.api_endpoints: Set[str] = set()
        self.emails: Set[str] = set()

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ReconX/1.0; security-research)"
        })
        requests.packages.urllib3.disable_warnings()

    def run(self) -> Dict[str, Any]:
        """Execute crawl and return all discovered assets."""
        logger.info(f"[*] Starting recursive crawl (depth={self.depth}, threads={self.threads})")

        # Phase 1: Recursive crawl
        self._crawl_recursive(self.target, 0)

        # Phase 2: Probe interesting paths
        logger.info("[*] Probing interesting paths...")
        self._probe_interesting_paths()

        # Phase 3: Extract from JS files
        if self.extract_js and self.js_files:
            logger.info(f"[*] Extracting endpoints from {len(self.js_files)} JS files...")
            self._extract_from_js()

        total_urls = len(self.found_urls)
        logger.info(f"[+] Crawl complete: {total_urls} unique URLs discovered")

        # Build parameters summary (serializable)
        params_summary = {
            url: list(params)
            for url, params in self.parameters.items()
        }

        return {
            "urls":             sorted(self.found_urls),
            "js_files":         sorted(self.js_files),
            "parameters":       params_summary,
            "forms":            self.forms,
            "interesting_paths": self.interesting_found,
            "api_endpoints":    sorted(self.api_endpoints),
            "emails":           sorted(self.emails),
            "total_urls":       total_urls,
        }

    # ──────────────────────────────────────────────────────────────
    # Recursive Crawler
    # ──────────────────────────────────────────────────────────────
    def _crawl_recursive(self, start_url: str, current_depth: int):
        """BFS recursive crawl up to self.depth levels."""
        if current_depth > self.depth:
            return

        queue = deque([(start_url, 0)])
        level_batches: Dict[int, List[str]] = {0: [start_url]}

        processed = set()

        while queue:
            url, depth = queue.popleft()

            norm = normalize_url(url)
            if norm in processed or depth > self.depth:
                continue
            processed.add(norm)

            links = self._fetch_and_parse(url)
            if links is None:
                continue

            time.sleep(self.delay)

            for link in links:
                norm_link = normalize_url(link)
                if norm_link not in processed and is_same_domain(link, self.base_domain):
                    queue.append((link, depth + 1))
                    self.found_urls.add(link)

    def _fetch_and_parse(self, url: str) -> Optional[List[str]]:
        """Fetch a URL, extract links, params, forms, emails."""
        try:
            resp = self.session.get(
                url, timeout=self.timeout,
                allow_redirects=True, verify=False
            )
            content_type = resp.headers.get("Content-Type", "")

            self.found_urls.add(url)
            self.visited.add(url)

            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return []

            soup = BeautifulSoup(resp.text, "html.parser")
            links = []

            # Extract all anchor tags
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                abs_url = urljoin(url, href)
                parsed = urlparse(abs_url)
                # Clean fragment
                abs_url = urlunparse(parsed._replace(fragment=""))
                if parsed.scheme in ("http", "https"):
                    links.append(abs_url)

            # Extract form actions
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                abs_action = urljoin(url, action) if action else url
                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if name:
                        inputs[name] = itype
                self.forms.append({
                    "url":    abs_action,
                    "method": method,
                    "inputs": inputs,
                })
                if abs_action:
                    links.append(abs_action)

            # Extract query parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = set(parse_qs(parsed_url.query).keys())
                if url not in self.parameters:
                    self.parameters[url] = set()
                self.parameters[url].update(params)

            # Extract JS files
            if self.extract_js:
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(url, script["src"])
                    if urlparse(js_url).scheme in ("http", "https"):
                        self.js_files.add(js_url)

            # Extract emails
            emails = re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                resp.text
            )
            self.emails.update(emails)

            # Look for API endpoints in page source
            api_matches = API_PATTERN.findall(resp.text)
            for match in api_matches:
                abs_api = urljoin(url, match)
                self.api_endpoints.add(abs_api)

            logger.debug(f"  Crawled: {url} ({len(links)} links)")
            return links

        except requests.exceptions.TooManyRedirects:
            logger.debug(f"  Too many redirects: {url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"  Connection error: {url}")
        except requests.exceptions.Timeout:
            logger.debug(f"  Timeout: {url}")
        except Exception as e:
            logger.debug(f"  Error crawling {url}: {e}")
        return None

    # ──────────────────────────────────────────────────────────────
    # Interesting Path Probing
    # ──────────────────────────────────────────────────────────────
    def _probe_interesting_paths(self):
        """Probe a list of known sensitive/interesting paths."""

        def probe(path: str):
            url = self.base_url.rstrip("/") + path
            try:
                resp = self.session.head(
                    url, timeout=self.timeout,
                    allow_redirects=True, verify=False
                )
                if resp.status_code not in (404, 403, 410):
                    # Also try GET if HEAD returns 405
                    if resp.status_code == 405:
                        resp = self.session.get(
                            url, timeout=self.timeout,
                            allow_redirects=True, verify=False
                        )
                    entry = {
                        "url":         url,
                        "status_code": resp.status_code,
                        "path":        path,
                        "interesting": resp.status_code in (200, 301, 302, 401),
                    }
                    if resp.status_code == 200:
                        self.found_urls.add(url)
                        logger.info(f"  [+] Interesting path [{resp.status_code}]: {url}")
                    elif resp.status_code in (301, 302):
                        location = resp.headers.get("Location", "")
                        entry["redirect"] = location
                        logger.debug(f"  [→] Redirect [{resp.status_code}]: {url} → {location}")
                    elif resp.status_code == 401:
                        logger.info(f"  [!] Auth required [{resp.status_code}]: {url}")
                    return entry
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe, path): path for path in INTERESTING_PATHS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.interesting_found.append(result)

    # ──────────────────────────────────────────────────────────────
    # JavaScript File Analysis
    # ──────────────────────────────────────────────────────────────
    def _extract_from_js(self):
        """Download JS files and extract endpoints/URLs from them."""

        def analyze_js(js_url: str):
            try:
                resp = self.session.get(
                    js_url, timeout=self.timeout, verify=False
                )
                if "javascript" not in resp.headers.get("Content-Type", "") \
                   and not js_url.endswith(".js"):
                    return

                content = resp.text

                # Extract URLs from JS
                for match in JS_URL_PATTERN.finditer(content):
                    path = match.group(1)
                    if path.startswith("/") or path.startswith("http"):
                        abs_url = urljoin(self.base_url, path)
                        if is_same_domain(abs_url, self.base_domain):
                            self.found_urls.add(abs_url)
                            logger.debug(f"  JS endpoint: {abs_url}")

                # Extract API patterns
                for match in API_PATTERN.findall(content):
                    abs_api = urljoin(self.base_url, match)
                    self.api_endpoints.add(abs_api)

            except Exception as e:
                logger.debug(f"  Error analyzing JS {js_url}: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            list(executor.map(analyze_js, list(self.js_files)[:50]))  # Cap at 50 JS files
