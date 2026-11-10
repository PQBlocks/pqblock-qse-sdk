# pqblocks-qse-sdk

Post-quantum cryptography SDK for ML-KEM, ML-DSA, and SLH-DSA (FIPS 203/204/205)

Part of the **PQBlocks** suite of post-quantum cryptography tools and high-assurance protocol adapters.
Maintained by The PQBlocks Authors under the Apache-2.0 license.

---

## Why PQBlocks / pqblocks-qse-sdk

Post-quantum algorithm migration requires rock-solid correctness, constant-time guarantees, and zero tolerance
for malformed input regressions. Standard legacy cryptographic stacks cannot handle the larger key sizes,
structured lattice matrices, or algebraic parameter sets mandated by modern NIST standards (FIPS 203 / ML-KEM, FIPS 204 / ML-DSA, FIPS 205 / SLH-DSA).

`pqblocks-qse-sdk` addresses this by providing:
1. **Deterministic Execution:** Strict validation bounds prevent buffer overruns and malformed wire structures.
2. **Standard Alignment:** Built specifically to satisfy the strict requirements of FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
3. **Zero-Overhead Integration:** Drop-in compatibility designed for modern backend, serverless, and embedded systems.
4. **Verified Correctness:** Covered by official NIST ACVP test vectors, automated fuzzing, and regression suites.

---

## Architecture

The system operates across three distinct structural tiers: input isolation, cryptographic core processing,
and serialized output verification.

```text
┌────────────────────────────────────────────────────────┐
│               Consumer / Application Layer             │
└───────────────────────────┬────────────────────────────┘
                            │ (Request / Data Input)
                            ▼
┌────────────────────────────────────────────────────────┐
│           Input Normalization & Bounds Check           │
│  ┌───────────────────────┐   ┌──────────────────────┐  │
│  │ Memory Range Asserts  │   │ Strict Type Enforcer │  │
│  └───────────────────────┘   └──────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ (Validated Parameters)
                            ▼
┌────────────────────────────────────────────────────────┐
│            Core Processing & Transform Engine          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ High-Assurance Computational Core                │  │
│  │ (Constant-Time Operations, Zero-Allocation Buff) │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ (Verified Output Payload)
                            ▼
┌────────────────────────────────────────────────────────┐
│               Output & Serialization Layer             │
└────────────────────────────────────────────────────────┘
```

The isolation boundaries ensure sensitive cryptographic buffers are tightly scoped and cleaned immediately
upon execution completion.

---

## Installation

Install the release package from PyPI or via direct Git reference:

```bash
pip install pqblocks-qse-sdk
```

Or install directly from the source repository:

```bash
pip install git+https://github.com/PQBlocks/pqblock-qse-sdk
```

### System Requirements
- Python >= 3.11
- Operating System: Linux (x86_64, aarch64), macOS (Apple Silicon / Intel), or Windows

---

## Usage

### Quickstart

```python
from pqblocks_qse_sdk import keypair, encapsulate, decapsulate, sign, verify

# Key encapsulation (ML-KEM-768)
pk, sk = keypair("ml-kem-768")
ct, ss_sender = encapsulate(pk, "ml-kem-768")
ss_receiver = decapsulate(sk, ct, "ml-kem-768")
assert ss_sender == ss_receiver

# Digital signature (ML-DSA-65)
pk_sig, sk_sig = keypair("ml-dsa-65")
sig = sign(sk_sig, b"sample payload", "ml-dsa-65")
valid = verify(pk_sig, sig, b"sample payload", "ml-dsa-65")
assert valid is True
print("Verified output:", valid)
```

### CLI Interface

Run directly from the terminal:

```bash
python -m pqblocks_qse_sdk --help
```

---

## API Reference

The public interface provides unified, high-level façades for post-quantum key encapsulation, digital signatures, deterministic test vector generation, and AST migration auditing.

### 1. Key Encapsulation Mechanism (FIPS 203 ML-KEM)

Unified KEM operations supporting `ml-kem-512`, `ml-kem-768`, and `ml-kem-1024`.

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `keypair(algorithm)` | `algorithm: str` | `Tuple[bytes, bytes]` | Generate public encapsulation key and secret decapsulation key pair using system CSPRNG (`os.urandom`). |
| `encapsulate(pk, algorithm)` | `pk: bytes, algorithm: str` | `Tuple[bytes, bytes]` | Encapsulate a freshly generated 32-byte shared secret against recipient public key `pk`. Returns `(ciphertext, shared_secret)`. |
| `decapsulate(sk, ct, algorithm)` | `sk: bytes, ct: bytes, algorithm: str` | `bytes` | Decapsulate shared secret from `ct` using secret key `sk`. Enforces FIPS 203 implicit rejection on invalid ciphertexts without leaking timing information. |

```python
from pqblocks_qse_sdk import keypair, encapsulate, decapsulate

pk, sk = keypair("ml-kem-768")
ct, ss_sender = encapsulate(pk, "ml-kem-768")
ss_receiver = decapsulate(sk, ct, "ml-kem-768")
assert ss_sender == ss_receiver
```

### 2. Digital Signatures (FIPS 204 ML-DSA & FIPS 205 SLH-DSA)

Unified digital signature operations supporting ML-DSA (`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`) and SLH-DSA parameter sets.

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `keypair(algorithm)` | `algorithm: str` | `Tuple[bytes, bytes]` | Generate public verification key and private signing key pair using system CSPRNG (`os.urandom`). |
| `sign(sk, message, algorithm)` | `sk: bytes, message: bytes, algorithm: str` | `bytes` | Generate a post-quantum digital signature for `message` using private signing key `sk`. |
| `verify(pk, signature, message, algorithm)` | `pk: bytes, signature: bytes, message: bytes, algorithm: str` | `bool` | Verify digital signature against `message` using verification key `pk`. Returns `False` on invalid signature or mismatched length without throwing exceptions. |

```python
from pqblocks_qse_sdk import keypair, sign, verify

pk, sk = keypair("ml-dsa-65")
sig = sign(sk, b"Secure transmission payload", "ml-dsa-65")
is_valid = verify(pk, sig, b"Secure transmission payload", "ml-dsa-65")
assert is_valid is True
```

### 3. Parameter Sizes & Length Validation

Direct access to NIST FIPS parameter dimensions and validation guards.

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `get_size(algorithm, field)` | `algorithm: str, field: str` | `int` | Query canonical size in bytes for `pk_len`, `sk_len`, `ct_len`, `ss_len`, or `sig_len`. |
| `validate_keymaterial_length(alg, name, val, expected)` | `alg: str, name: str, val: bytes, expected: int` | `None` | Validate that key material buffer matches expected FIPS byte length; raises `ValueError` on mismatch. |
| `validate_sig_length(alg, sig, expected)` | `alg: str, sig: bytes, expected: int` | `None` | Validate signature byte length against standard table for specified algorithm. |

### 4. Deterministic Corpus & PRNG Engine

Reproducible multi-algorithm test vector generation using 64-bit SplitMix PRNG and SHA-256 derivation.

| Symbol | Kind | Parameters / Signature | Description |
|---|---|---|---|
| `SplitMix64(seed)` | Class | `seed: int` | Fast 64-bit pseudo-random number generator with 64-bit state and modulo $2^{64}$ wrapping arithmetic. |
| `.next_u64()` | Method | `() -> int` | Advance internal state and return next pseudo-random unsigned 64-bit integer. |
| `.next_u32()` | Method | `() -> int` | Advance internal state and return next pseudo-random unsigned 32-bit integer. |
| `.to_bytes(length)` | Method | `(length: int) -> bytes` | Generate byte sequence of specified `length` from successive 64-bit little-endian words. |
| `SplitMix64_from_seed(seed)` | Function | `seed: bytes -> SplitMix64` | Initialize a `SplitMix64` instance from a 32-byte cryptographic seed. |
| `SplitMix64_from_i(master_seed, i)` | Function | `master_seed: bytes, i: int -> SplitMix64` | Derive $i$-th PRNG stream from `master_seed` using SHA-256 expansion. |
| `derive_seed(master_seed, i)` | Function | `master_seed: bytes, i: int -> bytes` | Compute deterministic 32-byte seed: `SHA-256(master_seed || i_be32)`. |
| `corpus_generate(output_dir, count, master_seed)` | Function | `output_dir: str, count: int = 100, master_seed: Optional[bytes] = None` | Write deterministic cross-language vector corpus into structured directory hierarchy. |

### 5. Static Analysis & Migration Guard

AST-based code scanner detecting deprecated classical cryptography implementations.

| Symbol | Kind | Parameters / Signature | Description |
|---|---|---|---|
| `harden_check_unsafe_api(target)` | Function | `target: Union[str, Any] -> Dict[str, Any]` | Scan Python file, directory tree, or module object for deprecated classical RSA/ECC cryptography imports. |
| `UnsafeAPIDetector` | Class | `ast.NodeVisitor` | AST visitor class that flags legacy `import rsa`, `import ec`, and `cryptography.hazmat.primitives.asymmetric` imports. |

```python
from pqblocks_qse_sdk import harden_check_unsafe_api

report = harden_check_unsafe_api("./my_service")
print(f"Detected {report["count"]} legacy cryptographic references:")
for finding in report["findings"]:
    print(f"  {finding["file"]}:{finding["line"]} - {finding["pattern"]} ({finding["severity"]})")
```

### 6. Exception Classes

Structured exception hierarchy for cryptographic operations.

| Exception Class | Base Class | Description |
|---|---|---|
| `QSEKemError` | `Exception` | Raised when an invalid KEM algorithm or malformed parameter is provided. |
| `QSESignError` | `Exception` | Raised when an invalid signature algorithm or malformed secret key is provided. |

### 7. CLI Command-Line Interface

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `main(argv=None)` | `argv: Optional[List[str]] = None` | `int` | CLI entry point supporting `--help`, status reporting, and deterministic corpus generation. |

---

## Limitations

- **Hardware Acceleration:** Native vector extensions (AVX-512 / ARM Neon) are leveraged where available, but pure fallback implementations are bound by runtime interpreter performance.
- **Algorithm Constraints:** Only standardized parameter sets are supported. Non-standardized variations are explicitly rejected to prevent security interoperability failures.
- **Memory Boundaries:** Maximum contiguous input buffers are restricted to prevent denial-of-service memory exhaustion.

---

## Security Notes

Security is designed into the component invariants:
- **Constant-Time Operations:** Critical primitive routines avoid secret-dependent branching or memory address lookups to mitigate side-channel leakage.
- **Implicit Rejection:** FIPS 203 KEM decapsulation returns a deterministic pseudo-random shared secret upon receiving an invalid ciphertext, mitigating adaptive chosen-ciphertext attacks.
- **Zeroization:** Sensitive memory structures, ephemeral buffers, and intermediate states are wiped immediately after use.
- **Entropy & Randomness:** Production key generation requires system cryptographically secure pseudorandom number generators (`os.urandom`).
- **Vulnerability Reporting:** Report suspected security issues through [GitHub Security Advisories](https://github.com/PQBlocks/pqblock-qse-sdk/security/advisories/new), open a security issue on GitHub, or contact the author / maintainers directly.
- **Validation Statement:** This package is verified against official NIST ACVP and Project Wycheproof vectors; it is not itself FIPS 140-3 / CMVP validated.

---

## Verification

Every release is continuously verified using rigorous test harnesses:
- **Official Vectors:** Known Answer Tests (KAT) verified against official published test corpuses.
- **Automated Fuzzing:** Continuous mutation fuzzing validating robustness against malformed payloads.
- **Audit:** Automated static analysis, type checking, and leak gates confirm clean boundaries.

Detailed reports are documented in:
- [TESTING.md](TESTING.md) — Comprehensive test execution and coverage details.
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) — Exact verification methodology and evidence.
- [BENCHMARKS.md](BENCHMARKS.md) — Latency, throughput, and memory consumption metrics.
- [SECURITY_NOTES.md](SECURITY_NOTES.md) — Threat model and defensive posture.

---

## Part of PQBlocks

`pqblocks-qse-sdk` is an integral part of the **PQBlocks** ecosystem, an open-source initiative providing production-ready,
verified post-quantum cryptographic primitives, containers, and migration tools.

- **GitHub:** [https://github.com/PQBlocks](https://github.com/PQBlocks)
- **License:** Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
- **Copyright:** (c) 2026 The PQBlocks Authors.
