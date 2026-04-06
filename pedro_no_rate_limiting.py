# ============================================================
# Author: Pedro Souza
# Vulnerability: Weak or Missing Rate Limiting
# Target: login.0x10.cloud
# ============================================================
#
# This script sends repeated login requests to check whether the
# target endpoint enforces rate limiting.
#
# Security risk:
# If a login form accepts many rapid attempts without blocking or
# slowing the client, attackers may automate brute-force or
# credential-guessing attacks.
#
# ============================================================

import urllib.request
import urllib.parse
import urllib.error
import json
import time

# Target login endpoint
url = "http://login.0x10.cloud"

# Test credentials
data = urllib.parse.urlencode({
    "username": "admin",
    "password": "wrongpassword"
}).encode()

# Number of requests to send
total_attempts = 11

# Keep track of results
success_count = 0
rate_limited_count = 0
other_errors = 0

print("Starting rate limit test...")
print(f"Target: {url}")
print(f"Attempts: {total_attempts}")
print("-" * 50)

for i in range(total_attempts):
    try:
        # Build and send POST request
        req = urllib.request.Request(url, data=data, method="POST")
        response = urllib.request.urlopen(req, timeout=5)

        # Read response body
        raw_body = response.read().decode("utf-8", errors="ignore")
        success_count += 1

        print(f"Attempt {i + 1}: HTTP {response.status}")

        # Try to parse JSON if available
        try:
            result = json.loads(raw_body)
            print("Response:", result)

            # If the endpoint explicitly says attempts are unlimited,
            # that is very strong evidence of missing rate limiting.
            if result.get("attempts") == "unlimited":
                print("VULNERABILITY: Endpoint reports unlimited attempts.")
        except json.JSONDecodeError:
            # If it is not JSON, just print a short preview
            print("Response preview:", raw_body[:100])

    except urllib.error.HTTPError as e:
        print(f"Attempt {i + 1}: HTTP {e.code}")

        if e.code == 429:
            rate_limited_count += 1
            print("Rate limiting detected: server returned 429 Too Many Requests.")
        else:
            other_errors += 1
            print(f"HTTP error: {e}")

    except Exception as e:
        other_errors += 1
        print(f"Attempt {i + 1}: Error: {e}")

    # Small delay between requests
    # The project instructions suggest adding a delay between requests
    time.sleep(0.2)

print("-" * 50)
print("Test summary:")
print(f"Successful responses: {success_count}")
print(f"429 rate-limited responses: {rate_limited_count}")
print(f"Other errors: {other_errors}")
print("-" * 50)

# Final conclusion
if rate_limited_count == 0 and success_count == total_attempts:
    print("VULNERABILITY: No effective rate limiting detected.")
    print("Security risk: repeated login attempts may allow brute-force attacks.")
elif rate_limited_count > 0:
    print("Rate limiting appears to be active.")
    print("This result does not strongly support a 'no rate limiting' vulnerability.")
else:
    print("Result inconclusive. Review the endpoint behavior manually.")