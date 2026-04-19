# ============================================================
#  AKIN CHECK: Exposed Backup File Accessible Without Authentication
#  Target: backup.0x10.cloud
#  Author: Akin Eludoyin
# ============================================================
#  This script checks common backup file paths on a target
#  subdomain. If a backup file is publicly accessible, it may
#  expose source code, credentials, configuration, or data.
# ============================================================

import urllib.request
import urllib.error
import time


def check_backup_files():
    # Set the target host and common backup file paths
    base_url = "http://backup.0x10.cloud"
    paths = [
        "/backup.zip",
        "/db.sql",
        "/.env",
    ]

    print("=" * 68)
    print("  Akin's Backup File Exposure Check")
    print("=" * 68)
    print(f"\n  Target: {base_url}")
    print("  Scanning...\n")

    found_any = False

    for path in paths:
        url = base_url + path
        try:
            # Request each possible backup file path
            response = urllib.request.urlopen(url, timeout=5)
            status_code = response.status

            if status_code == 200:
                print("  [!] VULNERABILITY FOUND")
                print(f"  Publicly accessible file: {url}")
                print("  Security Risk: backup files may expose sensitive data.\n")
                found_any = True
        except urllib.error.HTTPError:
            pass
        except urllib.error.URLError:
            pass

        
        time.sleep(0.15)

    if not found_any:
        print("  [OK] No exposed backup files detected on tested paths.")



if __name__ == "__main__":
    check_backup_files()