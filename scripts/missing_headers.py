"""
Author: Hooman
Vulnerability: Missing Security Headers
Target: search.0x10.cloud
"""

import urllib.request

def check_security_headers(url):
    try:
        print(f"Checking {url}...\n")

        response = urllib.request.urlopen(url, timeout=5)
        headers = dict(response.headers)

        missing = []

        if "X-Frame-Options" not in headers:
            missing.append("X-Frame-Options")

        if "Content-Security-Policy" not in headers:
            missing.append("Content-Security-Policy")

        if "X-Content-Type-Options" not in headers:
            missing.append("X-Content-Type-Options")

        if missing:
            print("VULNERABILITY FOUND:")
            print("Missing security headers:")
            for h in missing:
                print(f"- {h}")
            print("\nThese headers help protect against common web attacks.\n")
        else:
            print("All key security headers are present.\n")

    except Exception as e:
        print(f"Error: {e}")

def main():
    target = "http://search.0x10.cloud"
    check_security_headers(target)

if __name__ == "__main__":
    main()