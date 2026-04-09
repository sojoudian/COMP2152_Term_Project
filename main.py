# ============================================================
#  COMP2152 — Term Project: CTF Bug Bounty
#  Main Runner — Runs all vulnerability check scripts
# ============================================================

import subprocess
import sys
import os

# Instructor examples (starter demos)
EXAMPLE_SCRIPTS = [
    "example_http_check.py",
    "example_port_check.py",
    "example_header_check.py",
]

# Our vulnerability PoC (stdlib only; see assignment rules)
TEAM_SCRIPTS = [
    "bgirmadessalegn_ftp_anonymous.py",
]

if __name__ == "__main__":
    # Run scripts from the same directory as main.py
    script_dir = os.path.dirname(os.path.abspath(__file__))

    scripts = list(EXAMPLE_SCRIPTS)
    for name in TEAM_SCRIPTS:
        path = os.path.join(script_dir, name)
        if os.path.isfile(path):
            scripts.append(name)

    print("\n" + "=" * 50)
    print("  COMP2152 — Bug Bounty Scanner")
    print("  Running all vulnerability checks...")
    print("=" * 50, flush=True)

    for script in scripts:
        print(f"\n>>> Running {script}...\n", flush=True)
        script_path = os.path.join(script_dir, script)
        subprocess.run([sys.executable, script_path])

    print("\n" + "=" * 50)
    print("  All checks complete.")
    print("=" * 50 + "\n")
