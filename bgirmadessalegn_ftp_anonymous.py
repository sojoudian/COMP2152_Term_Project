
# Author: bgirmadessalegn
# Vulnerability: Anonymous FTP login allowed + banner version leak
# Target subdomain: ftp.0x10.cloud (port 2121 — non-standard FTP port)

# Many FTP servers disable anonymous access. Here, the server accepts
# anonymous credentials and exposes software version in the greeting.
# That weakens accountability and helps attackers pick known exploits.


import time
from ftplib import FTP, error_perm, error_temp, error_proto


def main() -> None:
    host = "ftp.0x10.cloud"
    port = 2121

    # --- Banner ---
    print("=" * 50)
    print("  FTP exposure — ftp.0x10.cloud (port 2121)")
    print("=" * 50)

    time.sleep(0.15)

    ftp = FTP()

    try:
        # --- Section: connect and capture banner (often leaks server/version) ---
        ftp.connect(host, port, timeout=15)
        welcome = ftp.getwelcome() or ""
        print(f"\n  Banner:\n  {welcome.strip().replace(chr(10), ' ')}")

        if "vsftpd" in welcome.lower() or "ftp" in welcome.lower():
            print("\n  [i] Banner discloses FTP software — useful for targeted exploits.")

        # --- Section: try anonymous session (common misconfiguration) ---
        time.sleep(0.15)
        ftp.login("anonymous", "guest@example.com")

        # --- Section: confirm authenticated context ---
        pwd_reply = ftp.sendcmd("PWD")
        print(f"\n  After anonymous login: {pwd_reply}")

        print("\n\nVULNERABILITY FOUND\n")
        print(" The server accepts anonymous FTP (no real user account).")
        print(" Anyone on the Internet can authenticate and reach the FTP")
        print(" filesystem context (here:", pwd_reply + ").")
        print(" Combined with a public version string, this aids reconnaissance")
        print(" and may allow file read/write if uploads or listings are enabled")
        print(" elsewhere. Anonymous FTP should be disabled unless required.")

        try:
            ftp.quit()
        except (error_perm, error_temp, error_proto, OSError, EOFError):
            # If the server drops the connection, ensure local cleanup below
            pass

    except error_perm as e:
        print(f"\n  [ERROR] FTP permission error: {e}")
    except (OSError, error_temp, error_proto, EOFError) as e:
        print(f"\n  [ERROR] Connection or protocol error: {e}")
    finally:
        try:
            ftp.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
