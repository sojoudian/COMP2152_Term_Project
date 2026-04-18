# Name: Alia Qureshi
# Student ID: 101535665
# Vulnerability: Open Telnet Port
# Target: telnet.0x10.cloud

import socket

try:
    target = "telnet.0x10.cloud"
    port = 23 

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"VULNERABILITY FOUND: Port {port} is OPEN")
        print("Telnet is insecure because it sends data in plain text")
    else:
        print("Port is closed")

    sock.close()

except Exception as e:
    print("Error:", e)