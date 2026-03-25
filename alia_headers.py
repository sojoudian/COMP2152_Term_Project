# Name: Alia Qureshi
# Student ID: 101535665
# Vulnerability: Missing Security Headers
# Target: api.0x10.cloud

import urllib.request

try:
    response = urllib.request.urlopen("http://api.0x10.cloud")
    headers = dict(response.headers)

    if "X-Frame-Options" not in headers:
        print("VULNERABILITY FOUND: Missing X-Frame-Options header")
        print("This allows clickjacking attacks")
    else:
        print("Header exists")

except Exception as e:
    print("Error:", e) 