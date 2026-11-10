# Security Architecture, Threat Model & Defensive Invariants — pqblocks-qse-sdk

Comprehensive threat model, side-channel mitigations, memory hygiene rules, and vulnerability reporting procedures for `pqblocks-qse-sdk`.

---

## 1. Security Architecture & Threat Model

`pqblocks-qse-sdk` is designed to provide high-assurance post-quantum key encapsulation (FIPS 203 ML-KEM) and digital signatures (FIPS 204 ML-DSA and FIPS 205 SLH-DSA). The threat model assumes adversaries with access to both classical computational power and future cryptanalytically relevant quantum computers (CRQCs).

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Threat Model & Protection Scope                 │
├───────────────────────────────────┬────────────────────────────────────┤
│         In-Scope Threats          │         Out-of-Scope Risks         │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Shor’s algorithm quantum attacks│ • Physical hardware fault injection│
│ • Store-Now-Decrypt-Later (SNDL)  │ • Host operating system compromise │
│ • Chosen-ciphertext attacks (CCA2)│ • Unauthorized root / debugger ptr │
│ • Timing side-channel leakage     │ • Malicious memory corruption in C │
│ • Non-canonical payload injections│ • Side-channels on unshielded IoT  │
└───────────────────────────────────┴────────────────────────────────────┘
```

---

## 2. What It Protects and What It Does Not

### Protected Capabilities
- **Post-Quantum Confidentiality (ML-KEM):** Protects session key exchanges against retrospective decryption by adversaries harvesting encrypted traffic today to decrypt with future quantum computers (Store-Now-Decrypt-Later).
- **Post-Quantum Authentication (ML-DSA / SLH-DSA):** Guarantees authenticity and non-repudiation of signatures against adversaries capable of forging RSA-3072 or ECDSA signatures via Shor’s discrete logarithm solver.
- **Adaptive Chosen-Ciphertext Security (IND-CCA2):** Protects decapsulation against active chosen-ciphertext attacks using strict Fujisaki-Okamoto transform implicit rejection.
- **Strict Boundary Integrity:** Rejects malformed lengths, non-canonical encodings, truncated keys, and corrupted wire headers cleanly without crashing or exposing uninitialized heap memory.
- **Codebase Migration Auditing:** Detects legacy classical cryptographic imports (`rsa`, `ec`, `dsa`) in Python source codebases via static AST traversal.

### Unprotected Boundaries (Out-of-Scope)
- **Host Compromise:** Does not protect if the host operating system, Python interpreter runtime, or hypervisor is subverted by malware or root privilege escalation.
- **Hardware Physical Side-Channels:** Does not protect against differential power analysis (DPA) or electromagnetic radiation (EM) probing on unshielded microcontrollers lacking hardware cryptographic accelerators.
- **Memory Dumping by Debuggers:** Does not defend against memory inspection by attached debuggers (`gdb`, `ptrace`) running with equal or higher user permissions.

---

## 3. Cryptographic Invariants & Defensive Posture

### 3.1 Constant-Time Execution & Side-Channel Mitigation
Lattice-based operations (polynomial multiplication, ring arithmetic, and vector inner products) are implemented without secret-dependent branching or secret-dependent table lookups. The underlying computational routines maintain fixed execution cycle counts independent of the secret key or ciphertext contents, preventing timing attacks.

### 3.2 FIPS 203 Implicit Rejection
In FIPS 203 ML-KEM, an active attacker may submit an invalid or manipulated ciphertext $c^*$ to observe whether the recipient system throws a decapsulation error or takes a different amount of time to fail (an active CCA attack).
`pqblocks-qse-sdk` strictly implements **implicit rejection**:
- If $c^*$ fails validation, the decapsulation engine does **not** raise an exception or abort early.
- Instead, it deterministically derives and returns a pseudo-random shared secret: $K = 	ext{HMAC-SHA256}(z, c^*)$, where $z$ is a pseudorandom value stored within the secret key.
- The decapsulation latency is identical for valid and invalid ciphertexts. The attacker receives no error code, timing signal, or side-channel leak. Subsequent symmetric decryption fails naturally without leaking secret key bits.

### 3.3 Zeroization & Memory Cleanliness
Sensitive key buffers and intermediate scalar states are securely overwritten upon function termination:
- Ephemeral decapsulation buffers are scrubbed immediately.
- Exception handlers guarantee cleanup of temporary buffers before unwinding the call stack.
- Garbage collection handles Python wrapper references, while native buffer layers overwrite memory blocks before deallocation.

### 3.4 Cryptographically Secure Randomness (CSPRNG)
Key generation operations strictly draw entropy from the platform operating system CSPRNG (`os.urandom` / Linux `getrandom(2)` / macOS `SecRandomCopyBytes`).
- **Seedable Keygen Prevention:** The `keypair()` function rejects user-supplied seeds in production to prevent catastrophic entropy exhaustion or guessable key material vulnerabilities (`API-SEEDABLE-SECRET` guard).
- **PRNG Isolation:** The `SplitMix64` engine is strictly reserved for deterministic test corpus generation and Known Answer Tests; it is completely decoupled from live cryptographic key generation.

### 3.5 Input Bounds Checking & DoS Prevention
To thwart algorithmic complexity and denial-of-service memory allocation attacks:
- Input lengths for public keys, secret keys, ciphertexts, and signatures are validated in $O(1)$ against fixed standard NIST dimension tables prior to executing any mathematical primitive.
- Out-of-bounds payloads are rejected with explicit, sanitized exceptions that reveal zero memory addresses or buffer contents.

---

## 4. Static Analysis AST Guard (`harden_check_unsafe_api`)

The SDK bundles an AST static analyzer designed for CI/CD migration pipelines:
- Inspects Python Abstract Syntax Trees without executing untrusted code.
- Detects deprecated legacy asymmetric primitives:
  - `import rsa`, `import ec`, `import dsa`
  - `from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding`
- Emits structured SARIF-compatible diagnostic findings with line numbers and remediation suggestions.

---

## 5. Vulnerability Reporting & Coordinated Disclosure

We take the security of `pqblocks-qse-sdk` seriously. If you identify a potential security vulnerability, follow these reporting guidelines:

### How to Report
1. **GitHub Private Security Advisory (Preferred):**  
   Submit a confidential report via GitHub:  
   [https://github.com/PQBlocks/pqblock-qse-sdk/security/advisories/new](https://github.com/PQBlocks/pqblock-qse-sdk/security/advisories/new)
2. **Confidential Issue / Contact Maintainers:**  
   Open an issue on GitHub requesting a private security coordination channel, or contact the author / repository maintainer directly:  
   **Govind Dubey** (`govinddubeycse@gmail.com`).

*Please do NOT file public issues or post details publicly on social media or forums before a fix has been validated and coordinated.*

### Response & Disclosure Timelines
- **Initial Acknowledgment:** Within 48 hours of report receipt.
- **Triage & Reproducer Assessment:** Within 5 business days.
- **Remediation & Patch Deployment:** Target within 30 days (maximum 90 days for complex upstream dependencies).
- **Public Disclosure & CVE Coordination:** Coordinated release with full credit to the security researcher in the security advisory.
