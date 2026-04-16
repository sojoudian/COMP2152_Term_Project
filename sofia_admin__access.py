# ============================================================
#  SOFIA CHECK: Publicly accessible admin panel
#  Target: admin.0x10.cloud
#  Author: Sofia Janik, 101573681
# ============================================================
#  Admin pages usually need authentication and authorization to be accessed. 
#  There is a clear warning on the page saying "This panel should not be publicly accessible!"
#  Currently any user can access the page without authentication or authorization which allows potential attackers to access sensitive data
# ============================================================

import urllib.request

target = "http://admin.0x10.cloud"

print("=" * 50)
print("  Admin Access Check")
print("=" * 50)

try:
    response = urllib.request.urlopen(target, timeout=5)
    final_url = response.url
    status = response.status
    content = response.read().decode("utf-8", errors="replace")

    print(f"\n  Target:     {target}")
    print(f"  Status:     {status}")
    print(f"  Final URL:  {final_url}")

    warning = "Warning: This panel should not be publicly accessible!"

    if warning in content: 
        print("\n  [!] VULNERABILITY FOUND")
        print("  The admin panel is accessible without authentication or authorization.")
        print("  This page explicitly warns that it should not be publicly accessible.")
        print("  This exposes sensitive information to attackers.")
    else:
        print("\n  [OK] No indication that the admin panel is accessible.")

except Exception as e:
    print(f"\n  [ERROR] Could not connect: {e}")

print("\n" + "=" * 50)