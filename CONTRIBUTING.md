# Contributing to ARECON 2.0

Thank you for your interest in contributing to **ARECON 2.0**!  
ARECON is an open-source, continuous attack surface management and reconnaissance framework created by **Rakshit Walia**.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Responsible Security Research Notice

ARECON is built strictly for **authorized security assessments, authorized bug bounty programs, and defensive security posture management**.  
Do NOT submit pull requests containing aggressive exploit payloads, unauthorized exploits, or destructive capabilities.

---

## How Can I Contribute?

### Reporting Bugs
- Check the existing issues before opening a new one.
- Provide a clear, detailed reproduction script or steps.
- Include your operating system (Windows, macOS, Linux) and Python version.

### Suggesting Enhancements
- Feature requests should align with our core architectural philosophy: **high-signal, zero-guessing, low-noise, and zero required external paid API keys**.
- Open an issue with the `enhancement` tag and detail the use case.

### Pull Requests
1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Follow PEP 8 guidelines and maintain documentation integrity:
   - Include type annotations (`typing`).
   - Add unit tests under `tests/` mocking any network or subprocess calls.
   - Ensure cross-platform compatibility across Windows, macOS, and Linux.
3. Run the automated test suite before opening your PR:
   ```bash
   python3 -m unittest discover -s tests -v
   ```
4. Push to your fork and submit a Pull Request against `main`.

---

## Coding Standards

- **Cross-Platform First:** Always use `os.path.join`, `pathlib`, or `tempfile.gettempdir()`. Never hardcode Unix `/tmp` or backslash paths.
- **Zero Hard Dependencies:** The core reconnaissance pipeline must remain runnable using Python's standard library.
- **Scope Governance:** Every active network capability must strictly respect `core.scope.ScopeFilter`.

---

## Author & Maintainer

- **Rakshit Walia**  
  GitHub: [@rakshitwalia](https://github.com/rakshitwalia)  
  Copyright (c) 2026 Rakshit Walia. All rights reserved.
