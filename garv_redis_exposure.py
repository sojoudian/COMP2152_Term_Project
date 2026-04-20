# ============================================================
#  COMP2152 — Term Project: CTF Bug Bounty
#  Vulnerability: Unauthenticated Redis Access + Info Disclosure
#  Target subdomain: redis.0x10.cloud (port 6379)
#  Author: Garv Dudy
# ============================================================
#
#  Redis should usually not be exposed publicly without protection.
#  If a Redis server allows unauthenticated commands, an attacker
#  may gather system details, enumerate configuration, or in some
#  cases read/write data.
#
#  This script connects to a Redis service using Python sockets,
#  sends simple Redis protocol commands, and checks whether the
#  server responds without authentication.
# ============================================================

import socket
import time

HOST = "redis.0x10.cloud"
PORT = 6379


def send_redis_command(sock, *parts):
    """
    Send a command using the Redis RESP protocol.
    Example: send_redis_command(sock, "PING")
             send_redis_command(sock, "INFO", "server")
    """
    payload = f"*{len(parts)}\r\n"
    for part in parts:
        payload += f"${len(part)}\r\n{part}\r\n"

    sock.sendall(payload.encode())
    return sock.recv(4096).decode(errors="ignore")


def main():
    print("=" * 60)
    print("  Redis Exposure Check")
    print("=" * 60)
    print(f"\n  Target: {HOST}")
    print(f"  Port:   {PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        time.sleep(0.15)  # respect rate limit guidance
        sock.connect((HOST, PORT))
        print("\n  Connected successfully.")

        # --- Check 1: basic Redis response ---
        print("\n  [1] Sending PING command...")
        ping_reply = send_redis_command(sock, "PING")
        print(f"      Reply: {ping_reply.strip()}")

        # --- Check 2: ask for server info ---
        print("\n  [2] Requesting INFO server...")
        time.sleep(0.15)
        info_reply = send_redis_command(sock, "INFO", "server")

        preview = info_reply[:800].strip()
        print("      Response preview:")
        print("      " + preview.replace("\r\n", "\n      "))

        vulnerable = False

        if "+PONG" in ping_reply:
            vulnerable = True

        if "redis_version" in info_reply.lower():
            vulnerable = True

        print("\n" + "-" * 60)

        if vulnerable:
            print("  [!] VULNERABILITY FOUND")
            print("  The Redis service responds to commands without authentication.")
            print("  This allows attackers to confirm the service is exposed and")
            print("  may leak version or server details through INFO output.")
            print("  Public unauthenticated Redis access is a serious security risk.")
        else:
            print("  [OK] Redis did not expose useful unauthenticated information.")

    except socket.timeout:
        print("\n  [ERROR] Connection timed out.")
    except socket.gaierror as e:
        print(f"\n  [ERROR] DNS / address error: {e}")
    except OSError as e:
        print(f"\n  [ERROR] Network error: {e}")
    finally:
        sock.close()
        print("\n" + "=" * 60)


if __name__ == "__main__":
    main()