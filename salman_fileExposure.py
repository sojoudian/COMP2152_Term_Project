"""
Author: salman Alamin
Vulnerability: Directory Listing Enabled
Target: files.0x10.cloud
"""

import urllib.request

url = "http://files.0x10.cloud/"

try:
    # Send request to the server
    response = urllib.request.urlopen(url, timeout=5)

    html = response.read().decode()

    print("Connected to files.0x10.cloud")
    print("Status:", response.status)

    # Check for common directory listing indicators
    if "Index of /" in html or "Parent Directory" in html:
        print("\nVULNERABILITY FOUND")
        print("Directory listing is enabled on files.0x10.cloud.")
        print("Attackers could browse and download sensitive files.")

    # Check for common exposed file names
    common_files = [
        "backup.zip",
        "database.sql",
        "config.php",
        "users.txt",
        "passwords.txt"
    ]

    for file in common_files:
        try:
            file_url = url + file
            file_response = urllib.request.urlopen(file_url)

            if file_response.status == 200:
                print(f"\nEXPOSED FILE FOUND: {file}")
                print("This file is publicly accessible and could contain sensitive data.")

        except:
            pass

except Exception as e:
    print("Connection error:", e)