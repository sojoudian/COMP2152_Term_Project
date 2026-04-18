"""
Author: Ali
Vulnerability: API Endpoint Exposure / Search Reflection Check
Target: api.0x10.cloud, search.0x10.cloud, docs.0x10.cloud
"""

import urllib.request
import urllib.parse
import time

def fetch_url(url):
    try:
        print(f"\nChecking: {url}")
        response = urllib.request.urlopen(url, timeout=5)
        body = response.read().decode(errors="ignore")
        print(f"Status: {response.status}")
        return body
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return ""

def check_api_endpoints():
    print("\n=== API ENDPOINT CHECK ===")
    endpoints = [
        "http://api.0x10.cloud/",
        "http://api.0x10.cloud/users",
        "http://api.0x10.cloud/data",
        "http://api.0x10.cloud/admin",
        "http://docs.0x10.cloud/"
    ]

    for url in endpoints:
        body = fetch_url(url)

        if body:
            lower_body = body.lower()
            if "password" in lower_body or "token" in lower_body or "email" in lower_body:
                print("VULNERABILITY FOUND: Possible sensitive data exposure.")
            elif "{" in body and "}" in body:
                print("Interesting: Possible JSON/API response exposed.")
            elif "index of /" in lower_body:
                print("VULNERABILITY FOUND: Directory listing detected.")
        time.sleep(0.2)

def check_search_reflection():
    print("\n=== SEARCH INPUT CHECK ===")
    payloads = [
        "test",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "../../etc/passwd"
    ]

    base_url = "http://search.0x10.cloud/?q="

    for payload in payloads:
        encoded = urllib.parse.quote(payload)
        url = base_url + encoded
        body = fetch_url(url)

        if body:
            if payload in body:
                print(f"VULNERABILITY FOUND: Reflected input detected for payload: {payload}")
            elif "sql" in body.lower() or "syntax" in body.lower() or "error" in body.lower():
                print(f"Interesting: Error-based response detected for payload: {payload}")
        time.sleep(0.2)

def main():
    check_api_endpoints()
    check_search_reflection()

if __name__ == "__main__":
    main()