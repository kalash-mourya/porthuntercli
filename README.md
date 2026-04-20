# PortHunter 🔍

An advanced network port scanner built in Python. Fast, lightweight, no external dependencies (except optional `pyfiglet` for the banner).

---

## Features

- Multi-threaded scanning — up to 600 concurrent connections
- Service fingerprinting for 15 common services
- Risk classification (LOW / MEDIUM / INFO)
- Banner grabbing to capture service version info
- CIDR subnet scanning support
- 5 timing templates — from paranoid to insane
- JSON export for automation / SIEM integration
- Works on Windows, Linux, macOS

---

## Requirements

- Python 3.7+
- No external packages required
- `pyfiglet` optional (just for the ASCII banner)

```bash
pip install pyfiglet  # optional
```

---

## Usage

```bash
python porthunter.py -H <target> [options]
```

### Examples

```bash
# scan a single IP (default ports 1-1024)
python porthunter.py -H 192.168.1.1

# scan top 15 common ports only
python porthunter.py -H 192.168.1.1 --top

# custom port range
python porthunter.py -H 192.168.1.1 -p 1-500

# grab banners
python porthunter.py -H 192.168.1.1 -b

# scan entire subnet
python porthunter.py -H 192.168.1.0/24 --top

# save results to json
python porthunter.py -H 192.168.1.1 --top -o results.json

# slow and stealthy
python porthunter.py -H 192.168.1.1 -T 1

# everything at once
python porthunter.py -H 192.168.1.1 -p 1-1024 -t 400 -T 3 -b -o out.json
```

---

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-H` | Target IP, hostname, or CIDR | required |
| `-p` | Port range | `1-1024` |
| `--top` | Scan top 15 ports only | off |
| `-t` | Thread count (max 600) | `400` |
| `-T` | Timing template 1–5 | `3` |
| `-b` | Enable banner grabbing | off |
| `-o` | Save output to JSON file | off |
| `-h` | Help | — |

---

## Timing Templates

| Template | Timeout | Retries | Use case |
|----------|---------|---------|----------|
| T1 — Paranoid | 2.0s | 1 | high latency / IDS evasion |
| T2 — Sneaky | 1.5s | 1 | slow and careful |
| T3 — Normal | 1.0s | 2 | default, works for most cases |
| T4 — Aggressive | 0.6s | 2 | fast local scans |
| T5 — Insane | 0.4s | 3 | fastest, most detectable |

---

## Services Detected

| Port | Service | Category | Risk |
|------|---------|----------|------|
| 21 | FTP | Remote Access | MEDIUM |
| 22 | SSH | Remote Access | MEDIUM |
| 23 | Telnet | Remote Access | INFO |
| 25 | SMTP | Mail | INFO |
| 53 | DNS | Infrastructure | INFO |
| 80 | HTTP | Web | LOW |
| 110 | POP3 | Mail | INFO |
| 139 | NetBIOS | Windows | INFO |
| 143 | IMAP | Mail | INFO |
| 443 | HTTPS | Web | LOW |
| 445 | SMB | Windows | MEDIUM |
| 3306 | MySQL | Database | INFO |
| 3389 | RDP | Remote Access | MEDIUM |
| 5432 | PostgreSQL | Database | INFO |
| 8080 | HTTP-Alt | Web | LOW |

---

## Sample Output

```
═══════════════════════════════════════════════════════════
HOST REPORT
═══════════════════════════════════════════════════════════
IP Address  : 192.168.1.1
Hostname    : router.local
IP Version  : IPv4
Status      : Up
Open Ports  : 2

[+] Port 22/tcp
    Service   : ssh
    Category  : Remote Access
    Risk      : MEDIUM
    Banner    : SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[+] Port 80/tcp
    Service   : http
    Category  : Web
    Risk      : LOW
    Banner    : Apache/2.4.41 (Ubuntu)
```




