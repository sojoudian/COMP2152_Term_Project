# COMP2152 — Term Project: CTF Bug Bounty

## Team Name

BytePatrol-COMP2152

## Team Members

| Member | Vulnerability Found | Branch Name |
|--------|-------------------|-------------|
| bgirmadessalegn | Anonymous FTP + version banner on non-standard port | bgirmadessalegn_ftp_anonymous |

## Videos

Short video (max 3 minutes) per the assignment — add your YouTube link when it is uploaded:

- bgirmadessalegn: https://youtube.com/watch?v=_______

## Target

- Server: `0x10.cloud` and its subdomains
- Submission: http://submit.0x10.cloud
- Leaderboard: http://ranking.0x10.cloud

## Important: Rate Limit

The server allows **10 requests per second** per IP address. If you send requests too fast, you will get blocked (HTTP 429). Add a small delay between requests:

```python
import time
time.sleep(0.15)  # wait 150ms between requests
```

## Getting Started

1. Look at the three example scripts:
   - `example_http_check.py` — checks if a site uses HTTPS (uses `urllib`)
   - `example_port_check.py` — checks if a port is open (uses `socket`)
   - `example_header_check.py` — reads HTTP response headers for info leaks (uses `urllib`)
2. Run examples + this PoC: `python3 main.py`, or only your script: `python3 bgirmadessalegn_ftp_anonymous.py`
3. Submit your finding at http://submit.0x10.cloud (use script output or code as proof)

## Rules

- **Python standard library only** — `socket`, `urllib`, `ssl`, `json`, `base64`, `time`. No pip packages.
- **Only scan `*.0x10.cloud`** — do not scan any other domain.
- **Respect the rate limit** — 10 requests/second max.
