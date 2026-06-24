#!/usr/bin/env python3
"""
Port Scanner - scanner.py
Developed by Aadarsh Bonthula
Reference: Cybersecurity and Ethical Hacking Material, CodTech IT Solutions
           Chapter 4: Scanning & Enumeration (Sections 4.1, 4.2, 4.3)
"""

import socket
import threading
import argparse
import sys
from datetime import datetime
from queue import Queue

# ─── Globals ────────────────────────────────────────────────────────────────
open_ports   = []          # Shared list — all threads write here
print_lock   = threading.Lock()   # Prevents garbled console output
queue        = Queue()     # Thread-safe queue of ports to scan

# Common service names mapped to port numbers (banner fallback)
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# ─── Banner Grabbing ─────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to retrieve a service banner from an open port.

    Technique from Section 4.3 — Banner Grabbing & Service Fingerprinting.
    Sends a generic HTTP-style request; many services respond with version info.
    Falls back to common service name lookup if no banner is received.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send a generic probe — works for HTTP, FTP, SSH, SMTP
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        # Return first meaningful line only
        first_line = banner.split("\n")[0].strip()
        return first_line if first_line else COMMON_SERVICES.get(port, "Unknown")

    except Exception:
        return COMMON_SERVICES.get(port, "Unknown")


# ─── Port Scan Worker ────────────────────────────────────────────────────────
def scan_port(ip: str, timeout: float):
    """
    Worker function — each thread pulls a port from the queue and tests it.

    Uses TCP Connect scan (Section 4.2, type 1.1):
    A full three-way handshake is attempted. If connect() succeeds → port is open.
    socket.error means the port is closed or filtered.
    """
    while not queue.empty():
        port = queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))   # Returns 0 on success
            sock.close()

            if result == 0:
                banner  = grab_banner(ip, port, timeout)
                service = COMMON_SERVICES.get(port, "Unknown")

                with print_lock:
                    print(f"  [OPEN]  Port {port:<6} | Service: {service:<15} | Banner: {banner}")
                    open_ports.append({
                        "port":    port,
                        "service": service,
                        "banner":  banner
                    })

        except socket.error:
            pass
        finally:
            queue.task_done()


# ─── Scan Orchestrator ───────────────────────────────────────────────────────
def run_scan(ip: str, start_port: int, end_port: int,
             threads: int, timeout: float):
    """
    Loads the port queue, spawns worker threads, waits for completion.

    Threading is critical here — scanning 1,000 ports sequentially would take
    minutes. With 100 threads, each handles ~10 ports concurrently.
    """
    print(f"\n{'='*60}")
    print(f"  Target   : {ip}")
    print(f"  Ports    : {start_port} – {end_port}")
    print(f"  Threads  : {threads}")
    print(f"  Timeout  : {timeout}s per port")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # Validate IP first
    try:
        socket.gethostbyname(ip)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {ip}")
        sys.exit(1)

    # Fill the queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # Spawn threads
    thread_list = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=scan_port, args=(ip, timeout), daemon=True)
        thread_list.append(t)
        t.start()

    # Wait for all threads to finish
    for t in thread_list:
        t.join()

    return open_ports


# ─── Report Generator ────────────────────────────────────────────────────────
def save_report(ip: str, results: list, output_file: str):
    """
    Writes a plain-text scan report — mimics the reporting phase of ethical
    hacking described in Chapter 1 (Key phases: Reporting).
    """
    with open(output_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  PORT SCAN REPORT\n")
        f.write(f"  Target  : {ip}\n")
        f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        if results:
            f.write(f"  {len(results)} open port(s) found:\n\n")
            f.write(f"  {'Port':<8} {'Service':<18} {'Banner'}\n")
            f.write(f"  {'-'*8} {'-'*18} {'-'*30}\n")
            for entry in sorted(results, key=lambda x: x["port"]):
                f.write(f"  {entry['port']:<8} {entry['service']:<18} {entry['banner']}\n")
        else:
            f.write("  No open ports found in the specified range.\n")

        f.write("\n" + "=" * 60 + "\n")

    print(f"\n[*] Report saved to: {output_file}")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner — Developed by Aadarsh Bonthula",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t 192.168.1.1
  python3 scanner.py -t 192.168.1.1 -p 1-1000 --threads 150
  python3 scanner.py -t scanme.nmap.org -p 22,80,443 -o report.txt
        """
    )
    parser.add_argument("-t", "--target",
                        required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports",
                        default="1-1024",
                        help="Port range: '1-1024' or comma-separated '22,80,443' (default: 1-1024)")
    parser.add_argument("--threads",
                        type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout",
                        type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output",
                        default=None,
                        help="Save report to file (e.g., report.txt)")

    args = parser.parse_args()

    # Parse port argument — supports both range and comma-separated
    if "-" in args.ports:
        parts = args.ports.split("-")
        start_port, end_port = int(parts[0]), int(parts[1])
    elif "," in args.ports:
        port_list = [int(p) for p in args.ports.split(",")]
        for p in port_list:
            queue.put(p)
        start_port, end_port = min(port_list), max(port_list)
    else:
        start_port = end_port = int(args.ports)

    results = run_scan(args.target, start_port, end_port,
                       args.threads, args.timeout)

    # Summary
    print(f"\n{'='*60}")
    print(f"  Scan complete. {len(results)} open port(s) found.")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    if args.output:
        save_report(args.target, results, args.output)


if __name__ == "__main__":
    main()
