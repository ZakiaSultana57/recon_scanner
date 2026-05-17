import subprocess

def run_recon(target):
    print("[+] Running Recon...")

    nmap = subprocess.getoutput(f"nmap -sV {target}")
    headers = subprocess.getoutput(f"curl -I {target}")

    return {
        "nmap": nmap,
        "headers": headers
    }
