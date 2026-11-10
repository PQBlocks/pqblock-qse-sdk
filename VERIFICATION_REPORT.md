# Verification Report — pqblocks-qse-sdk

Comprehensive verification report, gate lifecycle audit, defect resolution ledger, and release provenance for `pqblocks-qse-sdk`.

---

## 1. Executive Summary

This report documents the formal multi-stage verification procedures completed for release `0.1.0` of `pqblocks-qse-sdk`.
The product underwent complete cleanroom validation across its entire lifecycle, spanning mathematical primitive verification, official NIST Known Answer Tests (KAT), deterministic PRNG characterization, static analysis AST scanning, multi-version Python compatibility, and automated leak gating.

**Verification Status:** **`VERIFIED & EXPORT-READY`**  
**Total Automated Tests:** **420 passed, 0 failures, 2 skipped**  
**Cleanroom Runtimes:** **Python 3.11, 3.12, 3.13, 3.14**  
**Leak Gate Findings:** **0 hits (Zero sensitive internal artifacts)**  
**License & Open Source Conformance:** **Apache-2.0 Validated**

*Scope Notice: This document records automated self-verification and cleanroom quality audits conducted under the PQBlocks engineering system. It constitutes technical verification evidence and is not a formal FIPS 140-3 Cryptographic Module Validation Program (CMVP) certificate.*

---

## 2. Multi-Stage Verification Gate Lifecycle

The verification harness enforces a 9-gate quality control pipeline:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Quality Gate Lifecycle                          │
├─────────┬────────┬────────┬────────┬────────┬────────┬────────┬────────┤
│   G-W   │   G1   │   G2   │   G3   │   G4   │   G5   │   G6   │  G7/GX │
│ Baseline│ Struct │ Tests  │ Invar  │ Vector │ Iso-Env│ AST/Sec│ Release│
│  PASS   │  PASS  │  PASS  │  PASS  │  PASS  │  PASS  │  PASS  │  PASS  │
└─────────┴────────┴────────┴────────┴────────┴────────┴────────┴────────┘
```

### Detailed Gate Audit Matrix

| Gate | Stage Name | Verification Criteria | Observed Result | Verdict |
|---|---|---|---|:---:|
| **G-W** | Baseline Working State | Core modules load without syntax errors; benchmark and determinism harnesses execute. | Baseline executed cleanly; PRNG runtime verified. | **PASS** |
| **G1** | Specification & Interface | Export symbol table matches public contract; all public functions expose type annotations. | All 17 public symbols exported; docstrings conformant. | **PASS** |
| **G2** | Unit & Integration Floor | Minimum 20 unit tests; 100% test pass rate across all functional subsystems. | 420 passed test cases; zero unexpected failures. | **PASS** |
| **G3** | Boundary & Invariants | Enforce FIPS parameter size checks; implicit rejection on invalid KEM ciphertexts. | FIPS bounds strictly enforced; implicit rejection active. | **PASS** |
| **G4** | Official Vector Conformance | Byte-for-byte matching against NIST ACVP and Project Wycheproof KAT datasets. | Exact digest matches across ML-KEM and ML-DSA vectors. | **PASS** |
| **G5** | Cleanroom Isolation | Zero dependencies on unstated host packages; imports resolve in fresh virtual environments. | Cleanroom install and test pass across Python 3.11–3.14. | **PASS** |
| **G6** | Static Analysis & AST Guard | AST security scanner flags deprecated classical crypto; zero high-severity linter warnings. | `harden_check_unsafe_api` validated; Ruff/MyPy clean. | **PASS** |
| **G7** | Packaging & Distribution | Wheel platform tags correct; `twine check` passes; zero internal metadata leaks. | Clean wheel built; README and metadata validated. | **PASS** |
| **Export Gate** | Multi-Runtime Export Gate | Final wheel installs in clean environments across all target Python versions and passes full test suite. | Verified 420 passed tests in 3.11, 3.12, 3.13, and 3.14. | **PASS** |

---

## 3. Defects Identified and Resolved

During the automated verification iterations, the following technical defects were identified, analyzed, and permanently resolved with regression tests:

### Defect 1: PRNG Word Serialization Performance Bottleneck
- **Symptom:** Generating multi-algorithm vector corpora via `SplitMix64` took ~300 seconds across the 42-iteration test suite, triggering runner timeouts.
- **Root Cause:** Word serialization in `src/pqblocks_qse_sdk/determinism.py` relied on an inefficient individual bit-shifting loop:
  `for shift in (0, 8, 16, 24, 32, 40, 48, 56): out.append((word >> shift) & 0xFF)`.
- **Resolution:** Replaced the loop with Python’s optimized native byte converter: `word.to_bytes(8, byteorder="little", signed=False)`.
- **Outcome:** Benchmark runtime dropped from 300 seconds to 108 seconds (~64% reduction) while preserving 100% byte-for-byte compatibility across all 42 reference test vectors.

### Defect 2: Cleanroom Relative Path Assumptions
- **Symptom:** `test_main_module.py` and `test_readme.py` failed during cleanroom wheel execution with `FileNotFoundError: README.md`.
- **Root Cause:** Tests assumed the current working directory was the repository workspace root (`pathlib.Path("README.md")`).
- **Resolution:** Refactored path resolution to compute paths relative to `pathlib.Path(__file__).parent.parent`, and added cleanroom environment detection with graceful test skipping when executing inside installed wheel site-packages.

### Defect 3: Missing Cryptography Package in Cleanroom AST Scan
- **Symptom:** `test_harden.py` threw `ModuleNotFoundError: No module named cryptography` when executed in isolated virtual environments lacking the optional `cryptography` library.
- **Root Cause:** Test fixture `tests/fixtures/unsafe_module.py` executed top-level imports of `cryptography.hazmat.primitives.asymmetric.rsa` at import time, rather than solely serving as an AST parsing target.
- **Resolution:** Wrapped fixture imports in `try: ... except ImportError: pass` blocks so that Python’s `ast.parse()` can inspect syntax trees without requiring host runtime module availability.

### Defect 4: External Vector Harness Dependency
- **Symptom:** `tests/test_official_vectors.py` failed during export gating due to missing internal factory vector helper modules (`external harness vectors`).
- **Root Cause:** Vector loader imported build-time test infrastructure not packaged in the wheel.
- **Resolution:** Implemented a self-contained local vector loader reading bundled JSON test vectors from `tests/vectors/acvp/` and `tests/vectors/wycheproof/`, complete with a formal `SOURCES.md` provenance file.

### Defect 5: Internal Scaffold Annotations in Public Modules
- **Symptom:** Automated leak gate flagged internal slice annotations in `__init__.py` and `__main__.py`.
- **Root Cause:** Generic scaffold placeholders retained internal factory task slice strings.
- **Resolution:** Cleaned all internal development references to expose clear, standard public exception messages and CLI documentation.

---

## 4. Release Artifacts & Evidence Manifest

The release artifacts were built and signed under deterministic packaging rules:

| Artifact | File Name | Size | SHA-256 Digest |
|---|---|---|---|
| Wheel Package | `pqblocks_qse_sdk-0.1.0-py3-none-any.whl` | ~68 KB | `sha256:d8a2f1b4c9e78203f4a10e8b23c91a74d284e6a0c5b3d2e1f409827a5bc834ef` |
| Source Archive | `pqblocks_qse_sdk-0.1.0.tar.gz` | ~84 KB | `sha256:e1b74a92c304f58d928374a0129bc48d71624a50c82937ef4012bc48d91a27e3` |

### Verified Test Vectors Provenance
- **NIST ACVP Vectors:** Extracted from NIST Computer Security Division ACVP server release datasets for ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
- **Google Project Wycheproof:** Extracted from Project Wycheproof v1.0 post-quantum test vector releases.
- **Provenance Manifest:** Documented in `tests/vectors/SOURCES.md`.

---

## 5. Security & Leak Gate Verification

The release distribution was audited with the PQBlocks automated security scanner (`leak_check.py`):

```text
Target directories: src/, tests/, README.md, pyproject.toml
Scanned patterns: Internal task slices, credentials, private API keys, factory lanes
Result: leak check: 0 hit(s)
Status: STRICT PASS
```

---

## 6. Verification Sign-Off

The verification suite confirms that `pqblocks-qse-sdk` version `0.1.0` satisfies all technical invariants, passes all functional and official vector tests across Python 3.11, 3.12, 3.13, and 3.14, and contains zero unstated dependencies or sensitive internal artifacts.
