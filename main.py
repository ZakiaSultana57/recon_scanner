import argparse
from recon import run_recon
from crawler import crawl_recursive
from extractor import extract_data
from vulnscan import run_scans
from report import save_report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()

    target = args.target

    print("[+] Starting scan...\n")

    recon_data = run_recon(target)
    urls = crawl_recursive(target)
    extracted = extract_data(urls)
    vulns = run_scans(target)

    report = {
        "target": target,
        "recon": recon_data,
        "urls": urls,
        "extracted": extracted,
        "vulnerabilities": vulns
    }

    save_report(report)

if __name__ == "__main__":
    main()
