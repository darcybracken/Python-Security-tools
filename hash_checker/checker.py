#!/usr/bin/env python3
"""
File Integrity Hash Checker
Generates cryptographic hashes for files and compares against a known-good baseline.
Detects additions, deletions, and modifications.

Usage:
    python checker.py baseline <directory> [--output baseline.json]
    python checker.py check <directory> --baseline baseline.json

Author: D'Arcy Bracken
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def compute_hash(filepath, algorithm="sha256"):
    """Compute the hash of a file using the specified algorithm."""
    hash_func = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (PermissionError, OSError) as e:
        return f"ERROR: {e}"


def scan_directory(directory, algorithm="sha256"):
    """Walk a directory and compute hashes for all files."""
    results = {}
    directory = Path(directory).resolve()

    if not directory.is_dir():
        print(f"[ERROR] Not a directory: {directory}")
        sys.exit(1)

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            if filename.startswith("."):
                continue
            filepath = Path(root) / filename
            relative = str(filepath.relative_to(directory))
            file_hash = compute_hash(filepath, algorithm)
            file_size = filepath.stat().st_size if not file_hash.startswith("ERROR") else 0
            results[relative] = {
                "hash": file_hash,
                "size": file_size,
                "algorithm": algorithm,
            }

    return results


def create_baseline(directory, algorithm, output_file):
    """Scan directory and save baseline to JSON."""
    print(f"\n{'=' * 55}")
    print(f"  CREATING INTEGRITY BASELINE")
    print(f"  Directory:  {Path(directory).resolve()}")
    print(f"  Algorithm:  {algorithm.upper()}")
    print(f"  Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 55}\n")

    results = scan_directory(directory, algorithm)

    baseline = {
        "created": datetime.now().isoformat(),
        "directory": str(Path(directory).resolve()),
        "algorithm": algorithm,
        "file_count": len(results),
        "files": results,
    }

    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"  Scanned {len(results)} files")
    print(f"  Baseline saved to {output_file}")
    print(f"{'=' * 55}\n")

    return baseline


def check_integrity(directory, baseline_file, algorithm):
    """Compare current state against baseline and report changes."""
    try:
        with open(baseline_file, "r") as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Baseline file not found: {baseline_file}")
        sys.exit(1)

    baseline_files = baseline["files"]
    current_files = scan_directory(directory, algorithm)

    baseline_set = set(baseline_files.keys())
    current_set = set(current_files.keys())

    added = current_set - baseline_set
    deleted = baseline_set - current_set
    common = baseline_set & current_set

    modified = []
    unchanged = []
    for filepath in common:
        if current_files[filepath]["hash"] != baseline_files[filepath]["hash"]:
            modified.append(filepath)
        else:
            unchanged.append(filepath)

    report = []
    report.append("=" * 60)
    report.append("  FILE INTEGRITY CHECK REPORT")
    report.append(f"  Directory:     {Path(directory).resolve()}")
    report.append(f"  Baseline:      {baseline_file}")
    report.append(f"  Baseline date: {baseline.get('created', 'Unknown')}")
    report.append(f"  Checked:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"  Algorithm:     {algorithm.upper()}")
    report.append("=" * 60)

    if modified:
        report.append(f"\n[ALERT] MODIFIED FILES: {len(modified)}")
        report.append("-" * 60)
        for fp in sorted(modified):
            report.append(f"  {fp}")
            report.append(f"    Baseline: {baseline_files[fp]['hash'][:16]}...")
            report.append(f"    Current:  {current_files[fp]['hash'][:16]}...")
            size_diff = current_files[fp]["size"] - baseline_files[fp]["size"]
            sign = "+" if size_diff >= 0 else ""
            report.append(f"    Size:     {sign}{size_diff} bytes")

    if added:
        report.append(f"\n[WARNING] NEW FILES: {len(added)}")
        report.append("-" * 60)
        for fp in sorted(added):
            report.append(f"  + {fp} ({current_files[fp]['size']} bytes)")

    if deleted:
        report.append(f"\n[WARNING] DELETED FILES: {len(deleted)}")
        report.append("-" * 60)
        for fp in sorted(deleted):
            report.append(f"  - {fp}")

    total_issues = len(modified) + len(added) + len(deleted)
    status = "PASS" if total_issues == 0 else "FAIL"
    report.append(f"\n{'=' * 60}")
    report.append(f"  STATUS:     {status}")
    report.append(f"  Unchanged:  {len(unchanged)}")
    report.append(f"  Modified:   {len(modified)}")
    report.append(f"  Added:      {len(added)}")
    report.append(f"  Deleted:    {len(deleted)}")
    report.append(f"{'=' * 60}")

    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Hash Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python checker.py baseline /etc/nginx --output nginx_baseline.json\n"
               "  python checker.py check /etc/nginx --baseline nginx_baseline.json\n"
               "  python checker.py baseline ./webapp --algorithm md5\n",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bp = subparsers.add_parser("baseline", help="Create a new integrity baseline")
    bp.add_argument("directory", help="Directory to scan")
    bp.add_argument("--output", default="baseline.json", help="Output baseline file")
    bp.add_argument("--algorithm", choices=["md5", "sha1", "sha256"], default="sha256")

    cp = subparsers.add_parser("check", help="Check current state against baseline")
    cp.add_argument("directory", help="Directory to check")
    cp.add_argument("--baseline", required=True, help="Baseline JSON file to compare against")
    cp.add_argument("--algorithm", choices=["md5", "sha1", "sha256"], default="sha256")
    cp.add_argument("--output", help="Save report to file")

    args = parser.parse_args()

    if args.command == "baseline":
        create_baseline(args.directory, args.algorithm, args.output)
    elif args.command == "check":
        report = check_integrity(args.directory, args.baseline, args.algorithm)
        print(report)
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            print(f"\n  Report saved to {args.output}")


if __name__ == "__main__":
    main()
