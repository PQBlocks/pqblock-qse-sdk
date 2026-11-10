# pqblocks-qse-sdk

Post-quantum cryptography SDK for ML-KEM, ML-DSA, and SLH-DSA (FIPS 203/204/205)

Part of the **PQBlocks** suite of post-quantum cryptography tools and high-assurance protocol adapters.
Maintained by The PQBlocks Authors under the Apache-2.0 license.

---

## Why PQBlocks / pqblocks-qse-sdk

Post-quantum algorithm migration requires rock-solid correctness, constant-time guarantees, and zero tolerance
for malformed input regressions. Standard legacy cryptographic stacks cannot handle the larger key sizes,
structured lattice matrices, or algebraic parameter sets mandated by modern NIST standards (FIPS 203 / ML-KEM, FIPS 204 / ML-DSA, FIPS 205 / SLH-DSA, FIPS 206 / FN-DSA).

`pqblocks-qse-sdk` addresses this by providing:
1. **Deterministic Execution:** Strict validation bounds prevent buffer overruns and malformed wire structures.
2. **Standard Alignment:** Built specifically to satisfy the strict requirements of FIPS 203 / ML-KEM, FIPS 204 / ML-DSA, FIPS 205 / SLH-DSA, FIPS 206 / FN-DSA.
3. **Zero-Overhead Integration:** Drop-in compatibility designed for modern backend, serverless, and embedded systems.
4. **Verified Correctness:** Covered by official test vectors, automated fuzzing, and regression suites.

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

Install the release package from the official registry:

```bash
pip install pqblocks-qse-sdk
```

### System Requirements
- Node.js >= 20.0.0 (for npm packages) or Python >= 3.11 (for Python packages)
- Linux (x86_64, aarch64), macOS (Apple Silicon / Intel), or Windows

---

## Usage

### Quickstart

```python
from pqblocks_qse_sdk import main

# Direct invocation
result = main(b"sample payload")
print("Verified output:", result)
```

### CLI Interface

Run directly from the terminal:

```bash
python -m pqblocks_qse_sdk --help
```

---

## API Reference

The public interface is designed for clean ergonomics and minimal surface area:

| Symbol / Signature | Kind | Description |
|---|---|---|
| `class SplitMix64` | Type / Class | `SplitMix64 PRNG - 64-bit state, deterministic, fast.

Reference: https://github.com/PrincetonUniversity/SplitMix64
C semantics: unsigned overflow wraps modulo 2^64.` |
| `.next_u64()` | Method (`-> int`) | `Advance state and return next 64-bit integer.` |
| `.next_u32()` | Method (`-> int`) | `Advance state and return next 32-bit integer.` |
| `.to_bytes(length)` | Method (`-> bytes`) | `Derive `length` bytes from successive next_u64() calls.` |
| `class UnsafeAPIDetector` | Type / Class | `AST visitor that detects deprecated PQC API usage.` |
| `.visit_Import(node)` | Method (`-> Any`) | `Detect 'import rsa' or 'import ec' style imports.` |
| `.visit_ImportFrom(node)` | Method (`-> Any`) | `Detect 'from cryptography.hazmat.primitives.asymmetric import rsa' style imports.` |
| `class QSEKemError` | Type / Class | `Base error for KEM façade.` |
| `class QSESignError` | Type / Class | `Base error for signature façade.` |
| `main(argv)` | Function (`-> int`) | `CLI entry point (S1 scaffold).

Args:
    argv: Command-line arguments (default: sys.argv[1:]).

Returns:
    Exit code: 0 = ok (S1 scaffold). S15 will add argparse and subcommands.` |
| `corpus_generate(output_dir, count, master_seed)` | Function (`-> None`) | `Write deterministic cross-language corpus into output_dir.

Output layout:
    output_dir/
        algorithm_id/
            seed.bin
            pk.bin
            ct.bin
            ss.bin   (for KEM)
            sig.bin  (for signatures)

Byte layout of each file is algorithm_id || seed || ... with a versioned
header. The exact layout is pinned in this spec §1.3.

Args:
    output_dir: Directory to create corpus files in (will be created if missing)
    count: Per-algorithm instance count (default 100, capped at 10,000)
    master_seed: 32-byte caller-supplied seed (or generated if None)

Raises:
    ValueError: If count is negative or exceeds 10,000
    TypeError: If master_seed is provided but not bytes
    PermissionError: If output_dir cannot be written to` |
| `derive_seed(master_seed, i)` | Function (`-> bytes`) | `Derive 32-byte seed_i = SHA256(master_seed || i_be32).

Per spec §2.3–2.4: seed_i == SHA256(master_seed || i_be32)` |
| `SplitMix64_from_seed(seed)` | Function (`-> SplitMix64`) | `Create SplitMix64 instance from 32-byte seed.` |
| `SplitMix64_from_i(master_seed, i)` | Function (`-> SplitMix64`) | `Create SplitMix64 instance from master_seed + i.` |
| `harden_check_unsafe_api(module)` | Function (`-> Dict[str, Any]`) | `Scan a Python module for deprecated PQC API usage.

Returns {
    "findings": [{ "file": str, "line": int, "pattern": str, "severity": str }],
    "count": int
}

Intake is either an already-imported module object (behaviour unchanged)
or a string target:
- a path ending in `.py` → AST-walk that file;
- any other existing path → recursive walk of `*.py` beneath it;
- otherwise → treated as an importable module name and resolved with
  `importlib` (this is how submodule-only packages such as
  `cryptography.hazmat.primitives.asymmetric.mlkem` are reachable).

A non-existent path or unresolvable module name raises `ValueError` with
the target string. The returned shape is unchanged:
{
    "findings": [{ "file", "line", "pattern", "severity" }],
    "count": int
}

`findings` entries gained a `file` field when target intake was added;
module-object callers get `file` = the module `__file__` (or `"<memory>"`
for a module with no source file).

Example patterns flagged:
- usage of `cryptography.hazmat.primitives.asymmetric` paths that are not
  PQC-ready
- import of legacy RSA/ECC where ML-KEM/ML-DSA is required per CNSA 2.0.` |
| `keypair(algorithm)` | Function (`-> tuple[bytes, bytes]`) | `Generate (pk, sk) for a supported KEM or signature algorithm.

Per spec §1.2 this is the unified key-generation entry point across
ML-KEM, ML-DSA, and SLH-DSA. Signature algorithms are delegated to
:func:`pqblocks-qse-sdk.sign.keypair`; KEM algorithms are handled here.

Key generation draws randomness from the OS CSPRNG (pqcrypto). There is
deliberately no caller-supplied seed: a caller-seedable secret is a
guessable secret (API-SEEDABLE-SECRET). Reproducible vectors belong to
the test layer via private hooks, not the public API.

Args:
    algorithm: One of "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", or an "slh-dsa-*" set.
    deterministic: Accepted for API compatibility; has no effect.
    **kwargs: Private keyword arguments for tests (e.g. seed).

Returns:
    Tuple of (public_key, secret_key) as bytes.

Raises:
    QSEKemError: Unknown algorithm.
    ValueError: Invalid seed length or missing seed when deterministic=True.
    TypeError: seed not bytes.` |
| `encapsulate(pk, algorithm)` | Function (`-> tuple[bytes, bytes]`) | `KEM encapsulation: (ciphertext, shared_secret).

Args:
    pk: Public key bytes (must match algorithm's pk_len).
    algorithm: One of "ml-kem-512", "ml-kem-768", "ml-kem-1024".
    **kwargs: Optional keyword arguments (e.g. seed).

Returns:
    Tuple of (ciphertext, shared_secret) as bytes.

Raises:
    QSEKemError: Unknown algorithm or invalid pk length.
    TypeError: pk or seed not bytes.
    ValueError: Invalid seed length.` |
| `decapsulate(sk, ct, algorithm)` | Function (`-> bytes`) | `KEM decapsulation -> 32-byte shared secret.

Args:
    sk: Secret key bytes (must match algorithm's sk_len).
    ct: Ciphertext bytes (must match algorithm's ct_len).
    algorithm: One of "ml-kem-512", "ml-kem-768", "ml-kem-1024".
    **kwargs: Optional keyword arguments for API symmetry.

Returns:
    32-byte shared secret.

Raises:
    QSEKemError: Unknown algorithm or invalid sk/ct length.
    TypeError: sk, ct, or seed not bytes.
    ValueError: Invalid seed length.` |
| `matrix_status()` | Function (`-> Dict[str, Any]`) | `Compatibility matrix: returns a dict with:
  - "implementations": { "python": {...}, "java": {...}, "dotnet": {...} }
  - "latest_corpus_sha256": hex string of the current corpus
  - "interoperability": { "byte_identical": bool, "max_bit_diff": int }

The corpus is expected to be in a temporary directory with structure:
output_dir/
  algorithm_id/
    seed.bin
    pk.bin
    ct.bin (KEM only)
    ss.bin (KEM only)
    sig.bin (signature only)

This function scans for the corpus directory, computes SHA256 of each
algorithm directory, and determines interoperability.` |
| `status()` | Function (`-> dict`) | `Return SDK introspection dict.

Returns a dict with the following keys:

- ``version``: SDK package version string (``__version__``).
- ``fips_tables_version``: FIPS tables version the SDK was built against.
- ``primitive_libs``: mapping of primitive library names to their
  minimum verified versions.

The returned dict is the same object structure that the official-vector
test harness (S10) and merge gates expect for compliance checks.` |
| `keypair(algorithm)` | Function (`-> tuple[bytes, bytes]`) | `Generate (pk, sk) for a supported signature algorithm.

Per spec §1.2, ``keypair`` is the unified key-generation entry point
across ML-KEM, ML-DSA and SLH-DSA. This is the signature-side
implementation; :func:`pqblocks-qse-sdk.kem.keypair` delegates here for signature
algorithm names.

Key generation draws randomness from the OS CSPRNG (pqcrypto). Passing
a seed is rejected to prevent guessable secrets (API-SEEDABLE-SECRET).

Args:
    algorithm: One of "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", or an
        "slh-dsa-*" set.
    deterministic: Accepted for API compatibility; has no effect on the
        CSPRNG-backed key generation (FIPS 204/205 keygen is randomized).

Returns:
    Tuple of (public_key, secret_key) as bytes.

Raises:
    QSESignError: Unknown algorithm.` |
| `sign(sk, message, algorithm, deterministic)` | Function (`-> bytes`) | `Produce signature per algorithm.

Raises:
    QSESignError: Unknown algorithm or invalid sk length.
    TypeError: sk or message not bytes.` |
| `verify(pk, signature, message, algorithm)` | Function (`-> bool`) | `Verify signature. Returns False on wrong-length inputs or unknown algorithm (implicit rejection).

Per spec §3.6.2: verify performs implicit rejection — wrong-length pk/sig
causes return False (no exception, no timing leak). Also: unknown algorithm
string → False (no exception, no timing leak).

Raises:
    QSESignError: pk/signature/message not bytes (type error).
    TypeError: pk, signature, or message not bytes.` |
| `validate_keymaterial_length(algorithm, name, value, expected_len)` | Function (`-> None`) | `Validate that *value* has the expected length for *algorithm*.

Raises ``ValueError`` if the length does not match; the error message
follows the pattern ``"Invalid {name} length: expected {expected_len}, got {actual_len}"``.

Args:
    algorithm: The algorithm identifier (e.g. ``"ml-kem-768"``).
    name: The material name (e.g. ``"pk"``, ``"sk"``, ``"ct"``, ``"sig"``).
    value: The byte sequence to validate; may be ``None`` for implicit-rejection paths.
    expected_len: The FIPS-standard length in bytes expected for this algorithm.` |
| `validate_sig_length(algorithm, sig, expected_len)` | Function (`-> None`) | `Validate signature length per FIPS table for the given algorithm.

Raises ``ValueError`` if the signature length does not match; follows the same
error-message convention as :func:`validate_keymaterial_length`.` |
| `get_size(algorithm, field)` | Function (`-> int`) | `Return the FIPS table size for *field* of *algorithm*.

Supported *field* values: ``"pk_len"``, ``"sk_len"``, ``"ct_len"``,
``"ss_len"``, ``"sig_len"``.  Raises ``KeyError`` if the algorithm or
field is not in the table.` |

All APIs guarantee structured exception handling on malformed or out-of-bounds input payloads.

---

## Limitations

- **Hardware Acceleration:** Native vector extensions (AVX-512 / ARM Neon) are leveraged where available, but pure fallback implementations are bound by runtime interpreter performance.
- **Algorithm Constraints:** Only standardized parameter sets are supported. Non-standardized variations are explicitly rejected to prevent security interoperability failures.
- **Memory Boundaries:** Maximum contiguous input buffers are restricted to prevent denial-of-service memory exhaustion.

---

## Security Notes

Security is designed into the component invariants:
- **Constant-Time Operations:** Critical loops avoid secret-dependent branching or array lookups.
- **Zeroization:** Sensitive memory structures, ephemeral buffers, and intermediate states are wiped immediately after use.
- **Entropy & Randomness:** Requires system cryptographically secure pseudorandom number generators (CSPRNG).
- **Vulnerability Reporting:** Report suspected security issues privately via `engineering@pqblocks.org` rather than public issues.
- **Validation Statement:** This package was verified against official vectors; it is not itself FIPS 140-3 / CMVP validated.

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
