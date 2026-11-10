# Security Policy & Invariants - pqblocks-qse-sdk

Comprehensive security model, defensive invariants, and vulnerability handling for `pqblocks-qse-sdk`.

---

## What It Protects and What It Does Not

### Protects
- **Post-Quantum Resilience:** Protects cryptographic workflows against attacks by quantum computers capable of running Shor's algorithm.
- **Data Integrity:** Protects against unauthorized parameter alteration and corrupted wire structures.
- **Hostile Input Rejection:** Rejects malformed, non-canonical, or out-of-bounds payloads cleanly without crashing or exposing uninitialized memory.

### What It Does Not
- Does not defend against side-channel analysis on unshielded embedded hardware lacking hardware constant-time guarantees.
- Does not protect against local host root compromise or debugger attachment.

---

## Constant-Time Status

Critical algorithmic sections are constructed to avoid secret-dependent branches or secret-dependent table lookups,
minimizing timing side-channel leakage.

---

## Zeroization and Memory Cleanliness

Ephemeral key material and intermediate state buffers are securely overwritten (zeroized) upon completion or exception handling.

---

## Randomness & Entropy

All stochastic operations strictly require a high-quality system CSPRNG (Cryptographically Secure Pseudorandom Number Generator).
Weak PRNGs (such as standard `random` or pseudo-generators) are never utilized.

---

## Dependencies & Audit

- **Audited Core:** Built with minimal dependencies to ensure transparent auditing and supply chain security.
- **Vulnerability Reporting:** Report suspected vulnerabilities privately to `engineering@pqblocks.org`.
