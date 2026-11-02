# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

CyberTrace takes digital forensics security, memory boundaries, and evidence isolation seriously.
If you discover a security vulnerability or bypass (such as arbitrary command execution, path traversal, or memory leak):

1. **Do not create a public GitHub issue.**
2. Send an advisory detailing the technical vulnerability and proof-of-concept steps to the project maintainers.
3. We will acknowledge receipt within 48 hours and work with you to coordinate a disclosure and patch.

## Forensic Safety Invariants

- **No Remote Code Execution:** CyberTrace will never execute analyzed binaries or scripts.
- **Evidence Immutability:** Acquired evidence must remain byte-for-byte identical to its original source hash.
