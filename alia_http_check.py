# Name: Alia Qureshi
# Student ID: 101535665
# Vulnerability: HTTP instead of HTTPS
# Target: blog.0x10.cloud

import urllib.request

try:
    url = "http://blog.0x10.cloud"
    response = urllib.request.urlopen(url)

    if response.url.startswith("http://"):
        print("VULNERABILITY FOUND: Site is using HTTP")
        print("Data can be intercepted (MITM attack)")
    else:
        print("Secure HTTPS")

except Exception as e:
    print("Error:", e) 