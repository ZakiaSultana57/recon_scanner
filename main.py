#!/usr/bin/env python3
"""
ReconX - Automated Reconnaissance & Vulnerability Scanner
Main entry point for CLI execution.
"""

import argparse
import sys
import time
import os
from datetime import datetime

from modules.banner import print_banner
from modules.logger import setup_logger, get_logger
from modules.recon import ReconModule
from modules.crawler import CrawlerModule
from modules.vuln_scanner import VulnScannerModule
from modules.reporter import ReportGenerator
from modules.utils import validate_target, normalize_target

def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconX - Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t https://example.com --full
  python main.py -t 192.168.1.1 --recon-only
  python main.py -t example.com --depth 3 --threads 20 --html-report
  python main.py -t example.com --skip-vuln --output results/

IMPORTANT: Only scan targets you are authorized to test.
        """
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain, subdomain, URL, or IP address"
    )

    # Scan modes
    mode = parser.add_argument_group("Scan Modes")
    mode.add_argument("--full", action="store_true", help="Run full scan (recon + crawl + vuln scan)")
    mode.add_argument("--recon-only", action="store_true", help="Run reconnaissance only")
    mode.add_argument("--crawl-only", action="store_true", help="Run crawler only")
    mode.add_argument("--vuln-only", action="store_true", help="Run vulnerability scan only")
    mode.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability scanning")

    # Recon options
    recon = parser.add_argument_group("Reconnaissance Options")
    recon.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    recon.add_argument("--no-ports", action="store_true", help="Skip port scanning")
    recon.add_argument("--no-dns", action="store_true", help="Skip DNS enumeration")
    recon.add_argument("--no-headers", action="store_true", help="Skip HTTP header analysis")
    recon.add_argument("--no-tech", action="store_true", help="Skip technology detection")

    # Crawler options
    crawl = parser.add_argument_group("Crawler Options")
    crawl.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    crawl.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    crawl.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    crawl.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    crawl.add_argument("--no-js", action="store_true", help="Skip JavaScript file extraction")

    # Vuln scanner options
    vuln = parser.add_argument_group("Vulnerability Scanner Options")
    vuln.add_argument("--nikto", action="store_true", help="Run Nikto scanner")
    vuln.add_argument("--nuclei", action="store_true", help="Run Nuclei scanner")
    vuln.add_argument("--custom-checks", action="store_true", default=True, help="Run custom vulnerability checks (default: True)")
    vuln.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"], default="info",
                      help="Minimum severity to report (default: info)")

    # Output options
    output = parser.add_argument_group("Output Options")
    output.add_argument("--output", "-o", default="output/", help="Output directory (default: output/)")
    output.add_argument("--html-report", action="store_true", help="Generate HTML report")
    output.add_argument("--json-report", action="store_true", help="Generate JSON report")
    output.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    output.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and progress output")
    output.add_argument("--ai-summary", action="store_true", help="Generate AI-assisted findings summary (requires ANTHROPIC_API_KEY)")

    return parser.parse_args()


def main():
    args = parse_args()

    # Setup logger
    setup_logger(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger()

    # Print banner
    if not args.quiet:
        print_banner()

    # Validate target
    if not validate_target(args.target):
        logger.error(f"Invalid target: {args.target}")
        sys.exit(1)

    target = normalize_target(args.target)
    scan_start = datetime.now()

    logger.info(f"[*] Target: {target}")
    logger.info(f"[*] Scan started at: {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"[*] Output directory: {args.output}")

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Determine what to run
    run_recon = not args.crawl_only and not args.vuln_only
    run_crawl = not args.recon_only and not args.vuln_only
    run_vuln = not args.recon_only and not args.crawl_only and not args.skip_vuln

    if args.full:
        run_recon = run_crawl = run_vuln = True
    if args.recon_only:
        run_recon, run_crawl, run_vuln = True, False, False
    if args.crawl_only:
        run_recon, run_crawl, run_vuln = False, True, False
    if args.vuln_only:
        run_recon, run_crawl, run_vuln = False, False, True

    # Aggregate results
    results = {
        "target": target,
        "original_input": args.target,
        "scan_start": scan_start.isoformat(),
        "scan_end": None,
        "recon": {},
        "crawl": {},
        "vulnerabilities": [],
        "summary": {}
    }

    # ─── RECONNAISSANCE ───────────────────────────────────────────────
    if run_recon:
        logger.info("\n" + "="*60)
        logger.info("  PHASE 1: RECONNAISSANCE")
        logger.info("="*60)
        recon = ReconModule(
            target=target,
            skip_subdomains=args.no_subdomains,
            skip_ports=args.no_ports,
            skip_dns=args.no_dns,
            skip_headers=args.no_headers,
            skip_tech=args.no_tech,
            threads=args.threads,
            timeout=args.timeout,
        )
        results["recon"] = recon.run()

    # ─── CRAWLING ─────────────────────────────────────────────────────
    if run_crawl:
        logger.info("\n" + "="*60)
        logger.info("  PHASE 2: CRAWLING & ASSET DISCOVERY")
        logger.info("="*60)
        crawler = CrawlerModule(
            target=target,
            depth=args.depth,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            extract_js=not args.no_js,
        )
        results["crawl"] = crawler.run()

    # ─── VULNERABILITY SCANNING ───────────────────────────────────────
    if run_vuln:
        logger.info("\n" + "="*60)
        logger.info("  PHASE 3: VULNERABILITY SCANNING")
        logger.info("="*60)
        urls = results.get("crawl", {}).get("urls", [target])
        if not urls:
            urls = [target]

        scanner = VulnScannerModule(
            target=target,
            urls=urls,
            run_nikto=args.nikto,
            run_nuclei=args.nuclei,
            run_custom=args.custom_checks,
            min_severity=args.severity,
            threads=args.threads,
            timeout=args.timeout,
        )
        results["vulnerabilities"] = scanner.run()

    # ─── REPORTING ────────────────────────────────────────────────────
    scan_end = datetime.now()
    results["scan_end"] = scan_end.isoformat()
    results["scan_duration"] = str(scan_end - scan_start)

    logger.info("\n" + "="*60)
    logger.info("  PHASE 4: GENERATING REPORTS")
    logger.info("="*60)

    reporter = ReportGenerator(
        results=results,
        output_dir=args.output,
        target=target,
        ai_summary=args.ai_summary,
    )

    # Always generate text/JSON report
    json_path = reporter.generate_json()
    logger.info(f"[+] JSON report saved: {json_path}")

    if args.html_report or args.full or True:  # always generate HTML
        html_path = reporter.generate_html()
        logger.info(f"[+] HTML report saved: {html_path}")

    # Print summary
    reporter.print_summary()

    logger.info(f"\n[*] Scan completed in {results['scan_duration']}")
    logger.info("[*] Remember: Only scan systems you are authorized to test.\n")


if __name__ == "__main__":
    main()
