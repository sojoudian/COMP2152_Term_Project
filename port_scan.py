"""
Author: Hooman
Vulnerability: Open Port Detection
Target: telnet.0x10.cloud
"""

import socket

def check_port(target, port):
    try:
        print(f"Checking {target} on port {port}...\n")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(f"VULNERABILITY FOUND:")
            print(f"Port {port} is OPEN on {target}")
            print("Open ports may expose services that attackers can exploit.\n")
        else:
            print(f"Port {port} is closed on {target}\n")

        sock.close()

    except Exception as e:
        print(f"Error: {e}")

def main():
    target = "telnet.0x10.cloud"

    # try a few ports (important)
    ports = [23, 2323, 2121, 2525]

    for port in ports:
        check_port(target, port)

if __name__ == "__main__":
    main()