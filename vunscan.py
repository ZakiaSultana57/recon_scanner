import subprocess

def run_scans(target):
    print("[+] Running vulnerability scans...")

    nikto = subprocess.getoutput(f"nikto -h {target}")
    nuclei = subprocess.getoutput(f"nuclei -u {target}")

    return {
        "nikto": nikto,
        "nuclei": nuclei
    }
