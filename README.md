# Port Scanner

A fast, multithreaded TCP port scanner developed by **Aadarsh Bonthula** as part of a cybersecurity portfolio series focused on network security and ethical hacking fundamentals.

Built from scratch using Python's `socket` and `threading` libraries — no external dependencies required.

---

## What It Does

- Performs **TCP Connect scanning** across a defined port range
- Grabs **service banners** from open ports to identify software and versions
- Maps ports to **common service names** (SSH, HTTP, FTP, SMB, etc.)
- Runs **multithreaded** for fast scanning (100 concurrent threads by default)
- Exports a clean **plain-text report** with all findings

---

## Concepts Applied

| Concept | Reference |
|---------|-----------|
| TCP Connect Scan | Chapter 4.2 — Port Scanning with Nmap (CodTech Material) |
| Banner Grabbing | Chapter 4.3 — Banner Grabbing & Service Fingerprinting |
| Service Fingerprinting | Chapter 4.3 — Identifying running services on open ports |
| Network Scanning Phases | Chapter 4.1 — Introduction to Network Scanning |
| Reporting | Chapter 1 — Key phases of ethical hacking: Reporting |

---

## Requirements

- Python 3.7+
- No external libraries — uses only Python standard library

---

## Usage

```bash
# Basic scan (ports 1–1024)
python3 scanner.py -t 192.168.1.1

# Custom port range
python3 scanner.py -t 192.168.1.1 -p 1-5000

# Specific ports only
python3 scanner.py -t 192.168.1.1 -p 22,80,443,3306

# Custom threads and timeout
python3 scanner.py -t 192.168.1.1 -p 1-1000 --threads 150 --timeout 0.5

# Save report to file
python3 scanner.py -t 192.168.1.1 -p 1-1024 -o report.txt
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-t` / `--target` | Target IP or hostname | Required |
| `-p` / `--ports` | Port range or comma-separated list | `1-1024` |
| `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Socket timeout per port (seconds) | `1.0` |
| `-o` / `--output` | Save results to a text file | None |

---

## Sample Output

```
============================================================
  Target   : 192.168.1.1
  Ports    : 1 – 1024
  Threads  : 100
  Timeout  : 1.0s per port
  Started  : 2025-06-10 14:32:01
============================================================

  [OPEN]  Port 22     | Service: SSH             | Banner: SSH-2.0-OpenSSH_8.9
  [OPEN]  Port 80     | Service: HTTP            | Banner: HTTP/1.1 200 OK
  [OPEN]  Port 443    | Service: HTTPS           | Banner: Unknown

============================================================
  Scan complete. 3 open port(s) found.
  Finished : 2025-06-10 14:32:09
============================================================
```

---

## How It Works

### TCP Connect Scan
For each port in the range, a full TCP three-way handshake is attempted using `socket.connect_ex()`. A return value of `0` means the port is open and a service is actively listening.

### Threading
All ports are loaded into a thread-safe `Queue`. Worker threads pull ports from the queue concurrently, dramatically reducing total scan time compared to sequential scanning.

### Banner Grabbing
On open ports, a generic HTTP probe (`HEAD / HTTP/1.0`) is sent. Many services (HTTP, FTP, SMTP, SSH) respond with version information in their initial banner, revealing software and version details.

---

## Legal Disclaimer

This tool is developed for **educational purposes and authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may violate applicable laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation.

---

## Author

**Aadarsh Bonthula**
B.Tech Computer Science (Cybersecurity Specialization)
Manav Rachna International Institute of Research and Studies
Intern ID: CITS3364

GitHub: [NovocaineX](https://github.com/NovocaineX)

*Developed as part of a cybersecurity portfolio series focused on network security and ethical hacking fundamentals.*
