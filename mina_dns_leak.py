# ============================================================
# Vulnerability Check: Internal DNS Records Exposure
# Target: dns.0x10.cloud
# Author: Mina Fahim
# ============================================================
#
# This script checks whether dns.0x10.cloud publicly exposes
# internal DNS information such as private IP addresses,
# internal hostnames, or AXFR/zone transfer details.
#
# If these details are visible, attackers can learn the
# internal network structure of the organization.
# ============================================================

import urllib.request

target = "http://dns.0x10.cloud/zone"

print("=" * 55)
print("DNS Information Disclosure Check")
print("=" * 55)

try:
    response = urllib.request.urlopen(target, timeout=5)
    page = response.read().decode("utf-8", errors="ignore")

    print(f"\nTarget: {target}")
    print("Checking page content for sensitive DNS data...\n")

    findings = []

    if "AXFR" in page or "Zone transfer" in page:
        findings.append("Zone transfer (AXFR) information is exposed")

    if "internal" in page.lower():
        findings.append("Internal DNS records are exposed")

    if "db-master" in page or "db-replica" in page:
        findings.append("Internal database hostnames are exposed")

    if "10.0." in page:
        findings.append("Private internal IP addresses are exposed")

    if findings:
        print("[!] VULNERABILITY FOUND")
        for item in findings:
            print(f"- {item}")
        print("\nSecurity Risk:")
        print("This reveals internal network structure to attackers.")
    else:
        print("[OK] No obvious sensitive DNS information found.")

except Exception as e:
    print(f"[ERROR] Could not connect: {e}")

print("\n" + "=" * 55)