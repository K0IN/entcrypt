# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅                 |

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub issues.

Instead, report security issues to:

- **Email**: [thisk0in@gmail.com](mailto:thisk0in@gmail.com) (preferred)

### What to Include

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Resolution**: within 30 days (depending on severity)

We will keep you informed of the progress toward a fix and let you know when the vulnerability is addressed.

## Security Features

- AES-256-GCM authenticated encryption
- Random nonces for each encryption operation
- Pluggable key providers for key management
- Runtime security scanning (gosec + govulncheck)
- Codex security review for critical code paths
