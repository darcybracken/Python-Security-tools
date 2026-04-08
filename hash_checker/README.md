# File Integrity Hash Checker

Generates cryptographic hashes (MD5, SHA-1, SHA-256) for all files in a directory and compares against a known-good baseline to detect tampering.

## Why I Built This

File integrity monitoring shows up across multiple compliance frameworks — NIST CSF, PCI DSS, ISO 27001 — and it is a fundamental part of incident response. If an attacker modifies a config file, plants a backdoor, or deletes logs, you need a way to detect that something changed. Tools like OSSEC and Wazuh handle this in production, but I wanted to build the core logic myself to understand how baseline-and-compare integrity checking actually works.

## What It Does

### Baseline Mode (`baseline`)
- Walks an entire directory tree and computes a cryptographic hash for every file
- Stores the results in a JSON file with the hash, file size, and algorithm used
- This becomes your known-good snapshot — the state you trust

### Check Mode (`check`)
- Re-scans the same directory and compares every file against the stored baseline
- Flags three types of changes:
  - **Modified files** — the hash no longer matches, meaning the file content changed. The report shows the old and new hash plus the size difference so you can gauge the scope of the change.
  - **New files** — files that exist now but were not in the baseline. Could be legitimate additions or could be something an attacker dropped in.
  - **Deleted files** — files that were in the baseline but are now missing. Deleted log files during an incident are a red flag.

### Algorithm Support
- Defaults to SHA-256, which is the standard for integrity verification
- Also supports MD5 and SHA-1 for cases where you need to match an existing baseline or compare against vendor-provided checksums

## Usage

```bash
# Step 1: Create a baseline of a directory
python checker.py baseline /etc/nginx --output nginx_baseline.json

# Step 2: Later, check for changes
python checker.py check /etc/nginx --baseline nginx_baseline.json

# Use a different hash algorithm
python checker.py baseline ./webapp --algorithm sha1
```

## What I Learned

The part that clicked for me was how simple the core concept is — a hash is just a fingerprint, and if the fingerprint changes, the file changed. But the nuance is in what you baseline and when. If you baseline a directory after an attacker has already modified something, your "known-good" state is actually compromised. That is why integrity monitoring needs to be set up before an incident, not during one. I also learned why SHA-256 is preferred over MD5 for this — MD5 collisions are practical to generate, which means an attacker could theoretically modify a file and engineer it to produce the same MD5 hash as the original.