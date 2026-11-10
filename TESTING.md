# Testing Strategy & Test Execution Report — pqblocks-qse-sdk

Comprehensive testing methodology, test suite inventory, execution instructions, and coverage metrics for `pqblocks-qse-sdk`.

---

## 1. Testing Philosophy & Objectives

The `pqblocks-qse-sdk` testing framework is engineered to satisfy the highest assurance tier required for post-quantum cryptographic primitives and protocol adapters. Because post-quantum lattice-based algorithms operate over complex polynomial rings and structured matrices, software implementations must eliminate common failure modes including:

- **Algorithmic Correctness:** Bit-for-bit equivalence with official NIST Known Answer Tests (KAT) for FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
- **Constant-Time Execution & Implicit Rejection:** Verification that invalid, truncated, or forged ciphertexts trigger deterministic implicit rejection without timing or exception leaks.
- **Strict Boundary & Defensive Invariants:** Zeroization of sensitive key buffers, rejection of seedable secret bypasses, and validation of all input buffer lengths against normative FIPS tables.
- **Cross-Language & Deterministic Reproducibility:** Guaranteeing identical pseudorandom derivation across independent operating systems, CPU architectures, and language runtimes using 64-bit SplitMix PRNG and SHA-256 derivation.
- **Static Analysis & Migration Defense:** Verification that the built-in AST visitor (`UnsafeAPIDetector`) correctly identifies deprecated classical cryptographic primitives across diverse Python syntax patterns.

---

## 2. Test Execution & How to Run

### Standard Test Execution
Run the full test suite using `pytest` or Python’s built-in `unittest` discoverer:

```bash
# Set PYTHONPATH to include package sources
export PYTHONPATH=src

# Run complete test suite with verbose reporting
pytest tests/ -v

# Run with statement and branch coverage profiling
pytest tests/ -v --cov=pqblocks_qse_sdk --cov-report=term-missing --cov-report=html

# Alternative: Built-in unittest runner
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### Cleanroom Virtual Environment Execution
To guarantee isolation from host system packages and verify that all dependencies and entrypoints resolve cleanly:

```bash
# Create fresh isolated virtual environment
python3 -m venv /tmp/qse-cleanroom
source /tmp/qse-cleanroom/bin/activate

# Install package in editable or standard mode
pip install --upgrade pip
pip install .[test]

# Execute tests from cleanroom root
pytest tests/ -v
deactivate
rm -rf /tmp/qse-cleanroom
```

### Targeted Module Testing
Execute individual test modules to verify specific functional subsystems:

```bash
# 1. Official NIST ACVP & Wycheproof Known Answer Tests
pytest tests/test_official_vectors.py -v

# 2. Key Encapsulation Mechanism (ML-KEM-512/768/1024) Façade
pytest tests/test_kem_facade.py -v

# 3. Digital Signatures (ML-DSA-44/65/87 & SLH-DSA) Façade
pytest tests/test_sign_verify_facade.py -v

# 4. PRNG Determinism & Cross-Language Corpus Generation
pytest tests/test_determinism.py tests/test_corpus_generate.py -v

# 5. Static Analysis AST Security Auditing
pytest tests/test_harden.py -v

# 6. Edge Cases, Bounds Checking & Negative Tests
pytest tests/test_edge_cases.py tests/test_size_validation.py -v
```

---

## 3. Test Suite Inventory

The test harness consists of 16 specialized test modules containing over 420 automated unit, integration, and KAT test cases:

| Test Module | Primary Scope | Key Verifications & Assertions | Assertions |
|---|---|---|:---:|
| `tests/test_official_vectors.py` | Official NIST ACVP & Wycheproof KAT | Direct byte verification against published NIST ACVP JSON vectors for ML-KEM-512/768/1024 and ML-DSA-44/65/87. Validates shared secret and signature digests. | 64 |
| `tests/test_kem_facade.py` | FIPS 203 ML-KEM Operations | `keypair()`, `encapsulate()`, `decapsulate()` across all parameter sets. Asserts $ss_{sender} == ss_{receiver}$ and validates FIPS 203 implicit rejection on tampered ciphertext. | 38 |
| `tests/test_sign_verify_facade.py` | FIPS 204/205 Digital Signatures | `keypair()`, `sign()`, `verify()` across ML-DSA-44/65/87 and SLH-DSA. Tests valid signature verification, single-bit signature corruption rejection, and wrong-key rejection. | 44 |
| `tests/test_determinism.py` | SplitMix64 PRNG Engine | Validates 64-bit state transitions, unsigned 64-bit wrapping arithmetic, little-endian word serialization, seed expansion via SHA-256, and cross-platform output stability. | 42 |
| `tests/test_corpus_generate.py` | Test Vector Corpus Generation | Generates multi-algorithm test vector directory trees; verifies binary file headers, deterministic reproducibility, parameter alignment, and file permissions. | 28 |
| `tests/test_corpus_determinism.py` | Multi-Run Parity & Idempotence | Asserts byte-identical corpus generation across consecutive invocations with fixed seeds. | 16 |
| `tests/test_harden.py` | Static Analysis AST Auditing | AST inspection of Python files and module paths. Asserts detection of `import rsa`, `import ec`, `from cryptography... import rsa`, and recursive directory walks. | 32 |
| `tests/test_edge_cases.py` | Boundary & Negative Inputs | Zero-length payloads, buffer truncations, off-by-one lengths, wrong data types (`str` instead of `bytes`), empty strings, and unsupported algorithm identifiers. | 52 |
| `tests/test_sizes_fips_conformance.py` | FIPS 203/204/205 Parameter Tables | Strict comparison of `get_size()` queries against authoritative NIST standard specification tables for public keys, private keys, ciphertexts, and signatures. | 24 |
| `tests/test_size_validation.py` | Keymaterial & Signature Validation | Validates `validate_keymaterial_length()` and `validate_sig_length()` raising typed `ValueError` exceptions with informative diagnostics. | 26 |
| `tests/test_matrix_status.py` | Cross-Language Matrix Status | Verifies `matrix_status()` returns properly formatted metadata, supported algorithm maps, and determinism verification state. | 18 |
| `tests/test_status.py` | Subsystem Health & Readiness | Validates subsystem diagnostic reports and environment readiness checks. | 12 |
| `tests/test_smoke_import.py` | Public Interface & Symbol Exports | Asserts all public symbols are exposed at top-level `pqblocks_qse_sdk` namespace without unhandled circular imports. | 10 |
| `tests/test_main_module.py` | CLI Interface & Argument Parsing | CLI execution via `python -m pqblocks_qse_sdk`, `--help` flags, exit code verification, and terminal output contracts. | 8 |
| `tests/test_readme.py` | Documentation Quickstart Verification | Extracts and executes Python quickstarts directly from `README.md` to guarantee zero documentation rot. | 6 |

---

## 4. Multi-Layer Testing Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   Layer 5: Public API Contract & CLI                   │
│   (test_smoke_import.py, test_main_module.py, test_readme.py)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│              Layer 4: Static Analysis & Migration Defense              │
│       (test_harden.py, AST visitors, unsafe import pattern scans)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│             Layer 3: Cryptographic Façades & Invariants                │
│       (test_kem_facade.py, test_sign_verify_facade.py, bounds)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│              Layer 2: PRNG Determinism & Vector Corpora                │
│       (test_determinism.py, test_corpus_generate.py, SplitMix64)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│            Layer 1: Official NIST ACVP & Wycheproof KAT                │
│     (test_official_vectors.py, FIPS 203/204 Known Answer Vectors)      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Code Coverage Metrics

The test suite achieves comprehensive line and branch coverage across the entire codebase.

### Coverage Breakdown by Module

| Module Name | Statements | Missing | Branch Coverage | Statement Coverage | Status |
|---|:---:|:---:|:---:|:---:|:---:|
| `src/pqblocks_qse_sdk/__init__.py` | 36 | 0 | 100% | **100%** | Passed |
| `src/pqblocks_qse_sdk/kem.py` | 84 | 3 | 92.8% | **96.4%** | Passed |
| `src/pqblocks_qse_sdk/sign.py` | 96 | 4 | 91.6% | **95.8%** | Passed |
| `src/pqblocks_qse_sdk/determinism.py` | 112 | 2 | 96.4% | **98.2%** | Passed |
| `src/pqblocks_qse_sdk/harden.py` | 68 | 4 | 90.0% | **94.1%** | Passed |
| `src/pqblocks_qse_sdk/meta.py` | 24 | 0 | 100% | **100%** | Passed |
| `src/pqblocks_qse_sdk/__main__.py` | 38 | 3 | 87.5% | **92.1%** | Passed |
| **Total Codebase** | **458** | **16** | **93.5%** | **96.5%** | **Exceeds 80% Bar** |

---

## 6. Official Vector Conformance (KAT)

Official test vectors ensure conformance with the NIST Computer Security Division specifications:
1. **FIPS 203 ACVP Vectors:** Stored in `tests/vectors/acvp/`. Validates encapsulation public key parsing, ciphertext generation, and shared secret derivation against NIST intermediate and final values.
2. **FIPS 204 ACVP Vectors:** Tests ML-DSA signature generation and deterministic verification across all three parameter sets (44, 65, 87).
3. **Google Project Wycheproof Vectors:** Stored in `tests/vectors/wycheproof/`. Validates edge-case behavior against known malleability, non-canonical encodings, and malformed point representations.

---

## 7. Multi-Runtime & Continuous Integration Matrix

All releases are validated across the following matrix in continuous integration:

| Environment | Operating System | Architecture | Python Versions | Test Status |
|---|---|---|---|:---:|
| Linux Standard | Ubuntu 22.04 / 24.04 LTS | x86_64, aarch64 | 3.11, 3.12, 3.13, 3.14 | **420 passed (100%)** |
| macOS Native | macOS 14 Sonoma / 15 Sequoia | Apple Silicon (ARM64) | 3.11, 3.12, 3.13 | **420 passed (100%)** |
| Windows Native | Windows Server 2022 / Windows 11 | x86_64 | 3.11, 3.12, 3.13 | **420 passed (100%)** |

---

## 8. Defect Prevention & Regression Policy

No code modification is committed without:
1. A reproducer test demonstrating the target behavior or edge case.
2. Complete test suite execution with 100% pass rate.
3. Verification that statement coverage does not drop below 80%.
4. Zero static analysis violations reported by Ruff, Flake8, and MyPy.
5. Zero hits on automated leak scanners (`leak_check.py`).
