# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- **Port Scanner:** `parse_port_range` now validates `--ports` input. Reversed ranges (`10-1`), non-numeric input (`foo`), and out-of-range ports (`> 65535`) are rejected with a clear `[ERROR]` message and a clean exit, instead of crashing on an empty port list at `min()`/`max()`.

### Changed
- **Port Scanner:** Added a "Known Limitations" section to the README (IPv4-only resolution, TCP connect scan only, fixed timeout).
