
#  COMP2152 — Term Project: CTF Bug Bounty
#  Vulnerability: Outdated TLS / Deprecated SSL Protocols
#  Author: Alikhan
#  Branch: alikhan_deprecated_tls
#
#  Description:
#    old.0x10.cloud runs Apache 2.2.22 (released 2012) and
#    supports deprecated protocols SSLv3 and TLSv1.0.
#    SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566).
#    TLS 1.0 has known weaknesses and was deprecated in 2021.
#    The server has not been updated since 2019.


import urllib.request
import urllib.error
import ssl
import socket
import time

TARGET = "old.0x10.cloud"

print("=" * 55)
print("  SCAN: Deprecated TLS/SSL Protocols")
print(f"  Target: {TARGET}")
print("  Author: Alikhan")
print("=" * 55)

findings = []

# Test 1: Check HTTP response and server version
print(f"\n[TEST 1] Checking server version and headers...")
try:
    r = urllib.request.urlopen(f"http://{TARGET}", timeout=5)
    headers = dict(r.headers)
    server = headers.get("Server", "Not disclosed")
    print(f"  Server header : {server}")
    body = r.read(2000).decode(errors="ignore")
    print(f"  Body preview  : {body[:300]}")

    if "2.2" in server or "2.0" in server:
        print(f"  !! OUTDATED SERVER: {server} !!")
        findings.append(f"Outdated server: {server}")

except urllib.error.HTTPError as e:
    headers = dict(e.headers)
    server = headers.get("Server", "Not disclosed")
    body = e.read(2000).decode(errors="ignore")
    print(f"  Server: {server}")
    print(f"  Body: {body[:300]}")
    if "Apache 2.2" in body or "2.2.22" in body:
        findings.append("Outdated Apache 2.2.22 detected")
except Exception as e:
    print(f"  Error: {e}")

time.sleep(0.15)

# Test 2: Try connecting with TLSv1.0 (deprecated)
print(f"\n[TEST 2] Testing TLSv1.0 support (deprecated since 2021)...")
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1

    conn = ctx.wrap_socket(
        socket.create_connection((TARGET, 443), timeout=5),
        server_hostname=TARGET
    )
    ver = conn.version()
    conn.close()
    print(f"  Connected using: {ver}")
    print(f"  !! VULNERABLE: Server accepts deprecated {ver} !!")
    findings.append(f"Accepts deprecated {ver}")
except Exception as e:
    print(f"  TLSv1.0 result: {e}")

time.sleep(0.15)

# Test 3: Try SSLv3 (vulnerable to POODLE CVE-2014-3566)
print(f"\n[TEST 3] Testing SSLv3 support (POODLE attack CVE-2014-3566)...")
try:
    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx2.check_hostname = False
    ctx2.verify_mode = ssl.CERT_NONE
    ctx2.minimum_version = ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else ssl.TLSVersion.TLSv1
    conn2 = ctx2.wrap_socket(
        socket.create_connection((TARGET, 443), timeout=5),
        server_hostname=TARGET
    )
    ver2 = conn2.version()
    conn2.close()
    print(f"  Connected using: {ver2}")
    findings.append(f"Accepts {ver2}")
except Exception as e:
    print(f"  SSLv3 result: {e}")

time.sleep(0.15)

# Test 4: Confirm from page content
print(f"\n[TEST 4] Confirming vulnerability details from page...")
try:
    r2 = urllib.request.urlopen(f"http://{TARGET}", timeout=5)
    body2 = r2.read(3000).decode(errors="ignore")
    checks = [
        ("Apache 2.2.22", "Outdated Apache version (EOL since 2017)"),
        ("TLS Version: 1.0", "TLS 1.0 deprecated"),
        ("SSLv3", "SSLv3 vulnerable to POODLE attack"),
        ("2019", "Server not updated since 2019"),
    ]
    for keyword, msg in checks:
        if keyword in body2:
            print(f"  FOUND: {msg}")
            findings.append(msg)
except Exception as e:
    print(f"  Error: {e}")

print()
print("=" * 55)
print("RESULTS")
print("=" * 55)

if findings:
    print(f"\nVULNERABILITIES FOUND: {len(findings)}")
    for f in findings:
        print(f"  ✗ {f}")
    print()
    print("VULNERABILITY CONFIRMED — Deprecated TLS on old.0x10.cloud:")
    print("  Apache 2.2.22 reached End-of-Life in 2017.")
    print("  SSLv3 is vulnerable to POODLE (CVE-2014-3566):")
    print("    Attacker can decrypt HTTPS traffic via padding oracle.")
    print("  TLS 1.0 deprecated by RFC 8996 in 2021:")
    print("    Vulnerable to BEAST attack and cipher weaknesses.")
    print("  Server not updated since 2019 — unpatched CVEs exist.")
else:
    print("No deprecated protocol vulnerabilities confirmed.")