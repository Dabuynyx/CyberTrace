# Changelog

All notable changes to CyberTrace will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-02

### Added
- **Core Forensic Engine**: Orchestrator for pluggable forensic analyzers with deterministic output formatting.
- **File Intelligence Module**: Header signature matching, tri-hash calculation (MD5/SHA1/SHA256), Shannon entropy calculation, and extension masquerading detection.
- **Metadata Forensics Module**: ExifTool subprocess bridge and Pillow native fallback; chronological anomaly detection and GPS coordinate discovery.
- **Artifact Analysis Module**: Read-only SQLite parsers for Chromium (Chrome/Edge/Brave) and Firefox history, plus auth/system log parser.
- **Malware Triage Module**: Static PE and ELF binary parsing, suspicious Windows API detection, raw string extraction (URLs/IPs), and YARA scanning.
- **Evidence Correlation Engine**: Cross-case artifact correlation via identical cryptographic hashes and overlapping network/identity indicators.
- **Timeline Reconstruction**: Normalized timeline ordering of filesystem, browser, and authentication events.
- **Case Management System**: Complete CLI and SQLite database backing with cryptographic evidence verification.
- **Forensic Reporting Engine**: Automated report exports in JSON, HTML, and PDF formats.
- **Web Dashboard**: Local-first dark workstation forensic interface powered by FastAPI.
