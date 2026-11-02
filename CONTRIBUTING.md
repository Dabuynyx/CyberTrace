# Contributing to CyberTrace

Thank you for your interest in contributing to CyberTrace!

## Code Philosophy

1. **Deterministic Forensics:** Never fabricate findings, scores, or correlations.
2. **Local-First:** Core forensic modules must never require commercial or paid cloud APIs.
3. **Evidence Integrity:** Never modify source evidence in place.
4. **Minimal Bloat:** Clean, pythonic code with clear typing and test coverage.

## Development Workflow

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/CyberTrace.git
   cd CyberTrace
   ```
3. Set up the development virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
4. Run the test suite:
   ```bash
   pytest -v
   ```
5. Submit a descriptive Pull Request with tests covering any new forensic parsers or logic.
