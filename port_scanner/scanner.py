#!/usr/bin/env python3
"""
Simple TCP Port Scanner
Scans a target host for open ports using Python sockets.
Supports custom port ranges, timeouts, and outputs results to CSV.

Usage:
    python scanner.py <target> [--ports 1-1024] [--timeout 0.5] [--output results.csv]

Author: D'Arcy Bracken
"""

import argparse
import csv
import socket
import sys
from datetime import datetime


# Common service names for well-known ports
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL-UDP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
}


def parse_port_range(port_string):
    """Parse a port range string like '1-1024' or '80,443,8080' into a list of ports."""
    ports = []
    for part in port_string.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_port(target, port, timeout):
    """Attempt a TCP connection to a single port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except socket.error:
        return False


def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve hostname: {target}")
        sys.exit(1)


def run_scan(target, ports, timeout):
    """Scan all ports on the target and return a list of open port dicts."""
    ip = resolve_target(target)
    print(f"\n{'=' * 55}")
    print(f"  Target:     {target} ({ip})")
    print(f"  Ports:      {len(ports)} ports ({min(ports)}-{max(ports)})")
    print(f"  Timeout:    {timeout}s per port")
    print(f"  Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 55}\n")

    open_ports = []
    for i, port in enumerate(ports, 1):
        # Progress indicator every 100 ports
        if i % 100 == 0 or i == len(ports):
            pct = (i / len(ports)) * 100
            print(f"  Scanning... {i}/{len(ports)} ports ({pct:.0f}%)", end="\r")

        if scan_port(ip, port, timeout):
            service = COMMON_SERVICES.get(port, "Unknown")
            open_ports.append({
                "port": port,
                "state": "open",
                "service": service,
            })
            print(f"  [OPEN]  Port {port:<6} — {service:<15}")

    print(f"\n\n{'=' * 55}")
    print(f"  Scan complete: {len(open_ports)} open ports found")
    print(f"  Finished:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 55}\n")

    return open_ports


def export_csv(results, target, filename):
    """Export scan results to CSV."""
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["target", "port", "state", "service"])
        writer.writeheader()
        for r in results:
            writer.writerow({"target": target, **r})
    print(f"  Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python scanner.py 192.168.1.1\n"
               "  python scanner.py scanme.nmap.org --ports 1-100\n"
               "  python scanner.py 10.0.0.1 --ports 22,80,443 --output scan.csv\n",
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range to scan (default: 1-1024). Examples: 1-1024, 80,443,8080")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Timeout in seconds per port (default: 0.5)")
    parser.add_argument("--output", help="Export results to CSV file")

    args = parser.parse_args()
    ports = parse_port_range(args.ports)
    results = run_scan(args.target, ports, args.timeout)

    if args.output and results:
        export_csv(results, args.target, args.output)


if __name__ == "__main__":
    main()