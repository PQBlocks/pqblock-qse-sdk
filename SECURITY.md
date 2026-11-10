# Security Policy — pqblocks-qse-sdk

## Supported Versions

We provide security updates and vulnerability patches for the following versions:

| Version | Supported | Security Patch Cadence |
|---|:---:|---|
| `0.1.x` | **Yes** | Active security releases, critical fixes backported immediately. |
| `< 0.1.0` | No | Pre-release alpha builds. Please upgrade to `0.1.0`+. |

---

## Reporting a Vulnerability

If you discover a security issue or potential cryptographic vulnerability in `pqblocks-qse-sdk`, please report it responsibly:

### 1. Private Vulnerability Reporting (Preferred)
Submit a confidential vulnerability report directly through GitHub Security Advisories:  
👉 **[https://github.com/PQBlocks/pqblock-qse-sdk/security/advisories/new](https://github.com/PQBlocks/pqblock-qse-sdk/security/advisories/new)**

This enables secure, encrypted communication between you and the maintainers in a private channel before public release.

### 2. Contact the Author & Maintainers
If you cannot use GitHub Security Advisories, you can:
- Open a GitHub issue requesting a private security coordination channel:  
  **[https://github.com/PQBlocks/pqblock-qse-sdk/issues](https://github.com/PQBlocks/pqblock-qse-sdk/issues)**
- Contact the author directly:  
  **Govind Dubey** (`govinddubeycse@gmail.com`)

*Important: Please do NOT open public issue threads containing reproducible exploit payloads, proof-of-concept exploits, or vulnerable key material.*

---

## Response & Disclosure Process

We follow a coordinated disclosure process to protect users:

1. **Acknowledgment:** We aim to acknowledge receipt of all security reports within **48 hours**.
2. **Investigation & Triage:** We will investigate the report, verify the reproducer, and determine the severity rating according to CVSS v3.1 within **5 business days**.
3. **Patch Development:** A fix will be developed in a private security fork. We will share the proposed patch with the reporter for verification.
4. **Release & Advisory:** A patched version will be tagged and published on PyPI and GitHub. A GitHub Security Advisory will be published crediting the reporter (unless they request anonymity).
5. **Standard Disclosure Window:** We aim to remediate all confirmed issues within **30 days**, and no longer than **90 days**.

---

## Security Invariants & Scope

This policy covers code maintained within this repository (`src/pqblocks_qse_sdk/`).
Detailed architectural threat models, side-channel mitigations, and FIPS 203 implicit rejection invariants are documented in **[SECURITY_NOTES.md](SECURITY_NOTES.md)**.
