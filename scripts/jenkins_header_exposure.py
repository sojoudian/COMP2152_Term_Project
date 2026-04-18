"""
Author: Hooman
Vulnerability: Server Header Exposure
Target: api.0x10.cloud
"""

import urllib.request

def check_headers(url):
    try:
        print(f"Checking {url}...\n")

        response = urllib.request.urlopen(url, timeout=5)
        headers = dict(response.headers)

        server = headers.get("Server", "Not disclosed")
        powered_by = headers.get("X-Powered-By", "Not disclosed")

        print(f"Server: {server}")
        print(f"X-Powered-By: {powered_by}\n")

        if server != "Not disclosed":
            print("VULNERABILITY FOUND:")
            print("Server version is exposed in HTTP headers.")
            print("Attackers can use this information to find known exploits.\n")
        else:
            print("No server information exposed.\n")

    except Exception as e:
        print(f"Error: {e}")

def main():
    target = "http://jenkins.0x10.cloud"
    check_headers(target)

if __name__ == "__main__":
    main()