# TCP Port Scanner

Lightweight Python port scanner that identifies open TCP ports on a target host.

## Why I Built This

Port scanning is one of the first steps in any network reconnaissance workflow. Tools like Nmap handle this in production, but I wanted to understand what is actually happening at the socket level — how a TCP connection is initiated, what it means when a port responds versus times out, and how to map open ports back to known services.

This script uses only the Python standard library, so it runs anywhere Python is installed with zero dependencies. That matters in incident response situations where you might be working on a locked-down system without access to your usual toolkit.

## What It Does

- **TCP connect scanning** — attempts a full TCP handshake on each port using Python sockets. If the connection succeeds, the port is open. If it times out or is refused, the port is closed or filtered.
- **Service identification** — maps open ports to common service names (SSH on 22, HTTP on 80, RDP on 3389, etc.) so you can immediately see what is running without a separate lookup.
- **Flexible port targeting** — supports individual ports (`22,80,443`), ranges (`1-1024`), or a mix of both.
- **CSV export** — outputs results to a CSV file for documentation or for feeding into other tools during an assessment.

## Usage

```bash
# Scan default range (1-1024)
python scanner.py 192.168.1.1

# Scan specific ports
python scanner.py 10.0.0.1 --ports 22,80,443,3389

# Custom range with CSV export
python scanner.py scanme.nmap.org --ports 1-100 --timeout 1.0 --output results.csv
```

## What I Learned

The biggest takeaway was how much a timeout value affects scan speed and accuracy. Too low and you miss ports on slower networks. Too high and a full range scan takes forever. Nmap solves this with adaptive timing — this script uses a fixed timeout, which made me appreciate the engineering behind production scanning tools. I also learned why TCP connect scans are "noisy" compared to SYN scans: every open port gets a full three-way handshake, which means the target logs every connection attempt.