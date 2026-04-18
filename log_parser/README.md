# Security Log Parser

Parses authentication logs (SSH/PAM) and web server access logs (Apache/Nginx) to identify brute force attempts, scanner activity, and suspicious path access.

## Why I Built This

Log analysis is one of the first things a SOC analyst does when an alert fires. I wanted to build something that mirrors that workflow: pull a log file, parse it for patterns, and surface the entries that actually matter instead of scrolling through thousands of lines manually.

In production, you would use Splunk or an Elastic SIEM for this, but writing the logic from scratch forced me to understand what those tools are actually doing: regex matching against known log formats, counting event frequency per source IP, and correlating failed attempts with successful ones to spot possible compromises.

## What It Does

### Auth Log Mode (`--type auth`)
Reads standard syslog-format auth logs like `/var/log/auth.log` and looks for three things:

- **Brute force sources** - counts failed SSH login attempts per IP and flags any that exceed the threshold. In a real incident, these are the IPs you would feed into a firewall block list.
- **Targeted usernames** - shows which accounts attackers are guessing. You will almost always see `root` and `admin` at the top, but unexpected usernames can indicate the attacker has done prior reconnaissance.
- **Suspicious successes** - cross-references successful logins against IPs that also had failures. If an IP failed 50 times and then succeeded, that account may be compromised and needs immediate review.

### Web Log Mode (`--type web`)
Reads Apache/Nginx combined log format and flags:

- **High-frequency IPs** - request counts above the threshold usually mean automated scanners or bots, not real users.
- **Suspicious path access** - detects requests to paths like `/admin`, `/wp-login`, `/.env`, `/etc/passwd`, and `/.git`. These are the first things vulnerability scanners and attackers probe for on any web server.
- **Status code breakdown** - A spike in 404s or 403s often means someone is enumerating your directory structure, looking for something they should not have access to.

## Usage

```bash
# Parse SSH auth log for brute force attempts
python parser.py /var/log/auth.log --type auth

# Parse web access log with custom threshold
python parser.py access.log --type web --threshold 20

# Export report to file
python parser.py auth.log --type auth --output report.txt
```

## What I Learned

Building this reinforced how much signal is buried in raw logs that you would miss just by grepping for keywords. The correlation piece matching failed, and successful logins from the same IP were the most interesting part, because that is exactly the kind of logic SIEM alert rules are built on. It also made me appreciate why log format standardization matters so much. If every application logged differently, none of this automation would work.
