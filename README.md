# CyberTrace

<p align="center">
  <strong>"Every artifact tells a story. Find it. Verify it. Trace it."</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status">
  <img src="https://img.shields.io/badge/local--first-privacy%20focused-success.svg" alt="Local First">
</p>

---

## 🛡️ Overview

**CyberTrace** is an open-source, modular digital forensics and incident investigation framework engineered for security researchers, incident responders, malware analysts, SOC engineers, and CTF investigators.

CyberTrace operates strictly **local-first** and is independent of paid, cloud-hosted AI APIs. Every observation is deterministic, cryptographically hashed, and transparently grounded in low-level technical evidence.

---

## ✨ Core Capabilities

### 1. File Intelligence Engine
- **Deterministic Magic Signature Matching:** Accurate identification via magic bytes rather than fallible file extensions.
- **Extension Masquerading Detection:** Flags executable binaries disguised as innocuous documents (`.exe` disguised as `.png` or `.pdf`).
- **Cryptographic Tri-Hash:** Computes MD5, SHA-1, and SHA-256 in a unified streaming pass.
- **Shannon Entropy Analysis:** Computes byte distribution entropy (0.0 - 8.0) to pinpoint packed, encrypted, or compressed payloads.
- **Compound Extension Alerts:** Detects social engineering patterns like `document.pdf.exe`.

### 2. Advanced Metadata Forensics
- **Deep Metadata Extraction:** Integrated with `exiftool` and high-performance native Python fallbacks.
- **Chronological Anomaly Auditor:** Pinpoints timeline anomalies (such as file modification dates preceding creation timestamps).
- **Hardware & Software Profiling:** Detects camera makes, lenses, serials, and authoring software footprints.
- **GPS Extraction:** Uncovers embedded geographical coordinates.

### 3. Digital Artifact Analysis
- **Browser Forensics:** Safely inspects Chromium (Chrome, Edge, Brave) and Firefox SQLite profile stores in read-only mode.
- **System & Auth Log Extraction:** Extracts failed/successful SSH attempts, sudo escalations, and distinct remote IP indicators.

### 4. Static Malware Triage
- **Zero-Execution Architecture:** Safe, non-destructive static triage without running untrusted code.
- **PE & ELF Parsing:** Extracts section entropy, machine architecture, headers, and exports.
- **Hazardous API Detection:** Flags critical Windows APIs associated with process injection, hollowing, hooking, and persistence (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `URLDownloadToFile`).
- **Indicator Extraction:** Pulls embedded IPv4 addresses and URLs from raw binary strings.
- **YARA Integration:** Seamless scanning against custom or standard rule directories.

### 5. Evidence Correlation Engine & Multi-Artifact Relationship Graph
- Cross-correlates artifacts across an entire investigation.
- **Cryptographic Hash Matching:** Identifies duplicate artifacts and reused binaries across different evidence items.
- **Indicator Linkage:** Maps overlapping IPs, URLs, and user accounts.
- **Timeline Reconstruction:** Chronologically orders filesystem modifications, browser visits, and log events.

### 6. Case Management & Verification
- Distinct investigation cases with unique identifiers (`CASE-XXXXXXXX`).
- Immutable evidence repository with strict pre- and post-analysis hash verification.
- Tamper detection audit logs for every case operation.

### 7. Multi-Format Forensic Reporting
- Generates reproducible forensic reports in **HTML**, **JSON**, and **PDF** formats, complete with tool versions, hashes, technical findings, and limitations.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Dabuynyx/CyberTrace.git
cd CyberTrace

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .
```

*Optional System Tools:*
For extended metadata and YARA capability, install `exiftool` and `yara`:
- **macOS:** `brew install exiftool yara`
- **Linux (Debian/Ubuntu):** `sudo apt-get install exiftool yara`

---

## 💻 CLI Usage

Initialize the local repository and storage:
```bash
cybertrace init
```

Check system status:
```bash
cybertrace status
```

### Case Management
```bash
# Create a new investigation
cybertrace case create "APT Phishing Incident" --desc "Analysis of suspicious email attachments" --investigator "Adnan"

# List cases
cybertrace case list

# View case details
cybertrace case show CASE-XXXXXXXX
```

### Evidence Intake & Verification
```bash
# Add evidence to a case (auto-computes MD5, SHA-1, SHA-256 and copies safely)
cybertrace evidence add CASE-XXXXXXXX /path/to/suspicious_sample.bin

# Verify evidence integrity
cybertrace verify CASE-XXXXXXXX
```

### Forensic Analysis
```bash
# Direct scanning of standalone file or existing case
cybertrace scan /path/to/file.bin
cybertrace scan CASE-XXXXXXXX

# Run all forensic modules across all evidence in a case
cybertrace analyze case CASE-XXXXXXXX

# Or analyze a standalone file directly with specific modules:
cybertrace analyze file /path/to/file.bin
cybertrace analyze metadata /path/to/image.jpg
cybertrace analyze malware /path/to/binary.exe
cybertrace analyze artifact /path/to/History.db
```

### Correlation & Timeline
```bash
# View chronological timeline
cybertrace timeline CASE-XXXXXXXX

# Discover multi-evidence linkages
cybertrace correlate CASE-XXXXXXXX
```

### Generating Reports
```bash
# Generate HTML report
cybertrace report generate CASE-XXXXXXXX --format html

# Generate JSON report
cybertrace report generate CASE-XXXXXXXX --format json

# Generate PDF report
cybertrace report generate CASE-XXXXXXXX --format pdf
```

---

## 🖥️ Local Web Dashboard

Start the local forensic investigation dashboard:

```bash
uvicorn cybertrace.api.server:app --host 127.0.0.1 --port 8000
```
Open your browser to `http://127.0.0.1:8000` to access the interactive investigation console, or visit `http://127.0.0.1:8000/docs` for the interactive OpenAPI documentation.

---

## 🔒 Security & Forensic Integrity Principles

1. **Non-Destructive:** Original evidence is stored immutably; analysis is conducted on verified replicas.
2. **Zero Commercial AI Hallucinations:** Findings are derived strictly from deterministic parsers, headers, and signatures.
3. **Transparent Methodology:** Every finding cites its technical origin and limitations.
4. **Local-First Privacy:** No data or evidence leaves your workstation. Bound to `127.0.0.1` by default.
5. **Path Traversal & Size Protections:** Guard routines restrict file operations and prevent resource exhaustion.

---

## 🧪 Automated Testing

Run the automated test suite:
```bash
pytest -v
```

---

## 📜 License

Licensed under the [Apache License, Version 2.0](LICENSE).
