"""
Author: Hooman
Vulnerability: Insecure HTTP Communication
Target: dev.0x10.cloud
"""

import urllib.request

def check_http(url):
    try:
        print(f"Checking {url}...\n")

        response = urllib.request.urlopen(url, timeout=5)

        print(f"Final URL: {response.url}\n")

        if response.url.startswith("http://"):
            print("VULNERABILITY FOUND:")
            print("Website does not enforce HTTPS.")
            print("Data can be intercepted (man-in-the-middle attack).\n")
        else:
            print("Secure: HTTPS is being used.\n")

    except Exception as e:
        print(f"Error: {e}")

def main():
    target = "http://upload.0x10.cloud"
    check_http(target)

if __name__ == "__main__":
    main()