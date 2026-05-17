import json
import os
from datetime import datetime

def save_report(data):
    if not os.path.exists("output"):
        os.mkdir("output")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"output/report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"\n[+] Report saved: {filename}")
