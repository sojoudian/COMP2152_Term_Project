"""
Author: Amir
Vulnerability: Directory Listing / Sensitive File Exposure
Target: backup.0x10.cloud, storage.0x10.cloud, old.0x10.cloud, git.0x10.cloud
"""

import urllib.request
import time

def check_target(url):
    try:
        print(f"\nChecking: {url}")
        response = urllib.request.urlopen(url, timeout=5)
        body = response.read().decode(errors="ignore")
        print(f"Status: {response.status}")

        lower_body = body.lower()

        if "index of /" in lower_body:
            print("VULNERABILITY FOUND: Directory listing is enabled.")

        sensitive_items = [".env", "config.php", "backup", "secret", ".git", "database", "dump"]
        found_items = [item for item in sensitive_items if item.lower() in lower_body]

        if found_items:
            print("VULNERABILITY FOUND: Sensitive files or folders referenced:")
            for item in found_items:
                print(f"- {item}")

    except Exception as e:
        print(f"Error accessing {url}: {e}")

def main():
    targets = [
        "http://backup.0x10.cloud/",
        "http://storage.0x10.cloud/",
        "http://old.0x10.cloud/",
        "http://git.0x10.cloud/",
        "http://backup.0x10.cloud/.env",
        "http://storage.0x10.cloud/config.php",
        "http://old.0x10.cloud/.git/",
        "http://git.0x10.cloud/.git/"
    ]

    for url in targets:
        check_target(url)
        time.sleep(0.2)

if __name__ == "__main__":
    main()