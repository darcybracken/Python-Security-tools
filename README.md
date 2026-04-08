
---

# Python Security Tools

A collection of Python scripts for common security operations tasks network reconnaissance, log analysis, and file integrity monitoring. Built as hands-on portfolio projects.

## Tools

| Script | Purpose | Key Skills |
|---|---|---|
| [Port Scanner](./port_scanner) | TCP port scanning with service identification and CSV export | Socket programming, network recon |
| [Log Parser](./log_parser) | Auth and web log analysis for brute force and scanner detection | Log analysis, pattern matching, incident triage |
| [Hash Checker](./hash_checker) | File integrity baseline and change detection using SHA-256 | Integrity monitoring, incident response |

## Requirements

- Python 3.8+
- No external dependencies — all scripts use the Python standard library

## About

These tools are intentionally simple and dependency-free. In a real SOC, you would use Nmap, Splunk, and OSSEC/Wazuh for these tasks. The goal here is to demonstrate understanding of what those tools do under the hood and the ability to automate security workflows in Python.

## Author

D'Arcy Bracken — [LinkedIn](https://www.linkedin.com/in/darcyvbracken/) | [GitHub](https://github.com/darcybracken)
