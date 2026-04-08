#!/usr/bin/env python3
"""
Security Log Parser
Parses auth logs and web server access logs to identify suspicious activity.
Flags brute force attempts, unusual status codes, and high-frequency source IPs.

Usage:
    python parser.py <logfile> [--type auth|web] [--threshold 5] [--output report.txt]

Author: D'Arcy Bracken
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime


# Regex patterns for common log formats
PATTERNS = {
    "auth": {
        # Matches: Apr  8 09:15:32 server sshd[1234]: Failed password for user from 10.0.0.1 port 22 ssh2
        "failed_login": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)"
        ),
        # Matches: Apr  8 09:15:32 server sshd[1234]: Accepted password for user from 10.0.0.1 port 22 ssh2
        "success_login": re.compile(
            r"(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted \S+ for (\S+) from (\S+)"
        ),
    },
    "web": {
        # Matches common Apache/Nginx combined log format
        # 10.0.0.1 - - [08/Apr/2026:09:15:32 +0000] "GET /admin HTTP/1.1" 404 1234
        "access": re.compile(
            r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)'
        ),
    },
}


def parse_auth_log(filepath, threshold):
    """Parse authentication logs and identify brute force attempts."""
    failed_by_ip = Counter()
    failed_by_user = Counter()
    successful = []
    failed_entries = defaultdict(list)

    try:
        with open(filepath, "r") as f:
            for line in f:
                # Check for failed logins
                match = PATTERNS["auth"]["failed_login"].search(line)
                if match:
                    timestamp, user, ip = match.groups()
                    failed_by_ip[ip] += 1
                    failed_by_user[user] += 1
                    failed_entries[ip].append({"time": timestamp, "user": user})
                    continue

                # Check for successful logins
                match = PATTERNS["auth"]["success_login"].search(line)
                if match:
                    timestamp, user, ip = match.groups()
                    successful.append({"time": timestamp, "user": user, "ip": ip})
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    # Build report
    report = []
    report.append("=" * 60)
    report.append("  AUTHENTICATION LOG ANALYSIS")
    report.append(f"  Source: {filepath}")
    report.append(f"  Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"  Brute Force Threshold: {threshold} failed attempts")
    report.append("=" * 60)

    # Flag brute force IPs
    brute_force_ips = {ip: count for ip, count in failed_by_ip.items() if count >= threshold}
    report.append(f"\n[ALERT] Suspected Brute Force Sources: {len(brute_force_ips)}")
    report.append("-" * 60)
    if brute_force_ips:
        for ip, count in sorted(brute_force_ips.items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {ip:<20} — {count} failed attempts")
            # Show targeted usernames
            targeted_users = Counter(e["user"] for e in failed_entries[ip])
            for user, ucount in targeted_users.most_common(3):
                report.append(f"    └─ user: {user} ({ucount}x)")
    else:
        report.append("  None detected.")

    # Most targeted usernames
    report.append(f"\n[INFO] Most Targeted Usernames")
    report.append("-" * 60)
    for user, count in failed_by_user.most_common(10):
        flag = " ← HIGH" if count >= threshold else ""
        report.append(f"  {user:<20} — {count} failed attempts{flag}")

    # Successful logins (could indicate compromised account after brute force)
    report.append(f"\n[INFO] Successful Logins: {len(successful)}")
    report.append("-" * 60)
    for s in successful[-10:]:  # Show last 10
        suspicious = " ← REVIEW (IP also had failed attempts)" if s["ip"] in failed_by_ip else ""
        report.append(f"  {s['time']}  {s['user']:<12} from {s['ip']}{suspicious}")

    report.append(f"\n{'=' * 60}")
    report.append(f"  Total failed login attempts: {sum(failed_by_ip.values())}")
    report.append(f"  Unique source IPs:           {len(failed_by_ip)}")
    report.append(f"  Unique usernames targeted:   {len(failed_by_user)}")
    report.append(f"  Successful logins:           {len(successful)}")
    report.append(f"{'=' * 60}")

    return "\n".join(report)


def parse_web_log(filepath, threshold):
    """Parse web server access logs and identify suspicious patterns."""
    requests_by_ip = Counter()
    status_codes = Counter()
    error_paths = defaultdict(list)
    suspicious_paths = []

    # Paths that are commonly targeted by scanners
    SUSPICIOUS_KEYWORDS = [
        "/admin", "/wp-login", "/wp-admin", "/.env", "/phpmyadmin",
        "/shell", "/cmd", "/etc/passwd", "/config", "/.git",
        "/backup", "/db", "/sql", "/login", "/xmlrpc",
    ]

    try:
        with open(filepath, "r") as f:
            for line in f:
                match = PATTERNS["web"]["access"].search(line)
                if match:
                    ip, timestamp, method, path, status, size = match.groups()
                    status = int(status)
                    requests_by_ip[ip] += 1
                    status_codes[status] += 1

                    # Flag 4xx/5xx errors
                    if status >= 400:
                        error_paths[ip].append({"path": path, "status": status, "method": method})

                    # Flag suspicious path access
                    path_lower = path.lower()
                    if any(kw in path_lower for kw in SUSPICIOUS_KEYWORDS):
                        suspicious_paths.append({
                            "ip": ip, "path": path, "status": status, "method": method
                        })
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    # Build report
    report = []
    report.append("=" * 60)
    report.append("  WEB ACCESS LOG ANALYSIS")
    report.append(f"  Source: {filepath}")
    report.append(f"  Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 60)

    # High-frequency IPs (potential scanners/bots)
    scanner_ips = {ip: count for ip, count in requests_by_ip.items() if count >= threshold}
    report.append(f"\n[ALERT] High-Frequency IPs (>{threshold} requests): {len(scanner_ips)}")
    report.append("-" * 60)
    for ip, count in sorted(scanner_ips.items(), key=lambda x: x[1], reverse=True)[:15]:
        error_count = len(error_paths.get(ip, []))
        report.append(f"  {ip:<20} — {count} requests ({error_count} errors)")

    # Suspicious path access
    report.append(f"\n[ALERT] Suspicious Path Access Attempts: {len(suspicious_paths)}")
    report.append("-" * 60)
    for sp in suspicious_paths[:20]:
        report.append(f"  {sp['ip']:<20} {sp['method']:<6} {sp['path']:<30} → {sp['status']}")

    # Status code summary
    report.append(f"\n[INFO] Status Code Distribution")
    report.append("-" * 60)
    for code, count in sorted(status_codes.items()):
        bar = "█" * min(count, 40)
        report.append(f"  {code}  {count:>6}  {bar}")

    report.append(f"\n{'=' * 60}")
    report.append(f"  Total requests:       {sum(requests_by_ip.values())}")
    report.append(f"  Unique source IPs:    {len(requests_by_ip)}")
    report.append(f"  Suspicious accesses:  {len(suspicious_paths)}")
    report.append(f"{'=' * 60}")

    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Parser — analyze auth and web logs for suspicious activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python parser.py /var/log/auth.log --type auth\n"
               "  python parser.py access.log --type web --threshold 20\n"
               "  python parser.py auth.log --type auth --output report.txt\n",
    )
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--type", choices=["auth", "web"], default="auth",
                        help="Log type: auth (SSH/PAM) or web (Apache/Nginx)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Alert threshold for repeated events (default: 5)")
    parser.add_argument("--output", help="Save report to file")

    args = parser.parse_args()

    if args.type == "auth":
        report = parse_auth_log(args.logfile, args.threshold)
    else:
        report = parse_web_log(args.logfile, args.threshold)

    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n  Report saved to {args.output}")


if __name__ == "__main__":
    main()