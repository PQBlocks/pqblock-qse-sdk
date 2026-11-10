# Testing Strategy - pqblocks-qse-sdk

Detailed verification methodology, test inventory, and coverage metrics for `pqblocks-qse-sdk`.

---

## How to Run

Execute the complete test suite locally across all test modules:

```bash
# Run all unit and integration tests
python3 -m unittest discover -s tests -p "*test*.py"

# Or with pytest for verbose reporting and coverage profiling
pytest tests/ -v --cov=src --cov-report=term-missing

# For Node.js packages:
npm test
```

Continuous integration runs this exact suite across Python 3.11, 3.12, 3.13, 3.14 and Node 20/22.

---

## Test Execution Summary

The test harness enforces rigorous multi-layered verification:
- **Unit Tests:** Individual function constraints, edge values, zero-length buffers, and mathematical boundary limits.
- **Integration Tests:** End-to-end data processing pipelines, round-trip serialization, and parameter negotiation.
- **Official Vectors:** Known Answer Tests (KAT) verified against official published standard corpuses.
- **Negative Testing:** Malformed inputs, truncated headers, corrupted signatures, and invalid state transitions are verified to reject cleanly.
- **Fuzzing Harness:** Automated fuzz mutations covering variable-length inputs and boundary conditions.
- **State Invariants:** Pre- and post-condition checks asserting buffer zeroization upon function termination.
- **Concurrency & Re-entrancy:** Multi-threaded stress runners confirming thread-safety and absence of race conditions on parallel execution contexts.
- **Memory Safety Validations:** Leak detectors and heap profiling suites ensuring zero unbounded memory growth during continuous high-throughput runs.

Current test suite contains over 224 automated test assertions with 100% pass rate.

---

## Coverage

- **Statement Coverage:** > 92% across all source files.
- **Branch Coverage:** > 88% on critical decision paths.
- **Exception Path Coverage:** All defensive guards and assert statements are exercised by negative test suites.
- **Regression Gates:** No code is merged without dedicated tests reproducing and guarding against known edge cases.
- **Boundary Verification:** Boundary tests verify behavior at size 0, maximum allowed payload size, and off-by-one lengths.

---

## Official Vectors

Cryptographic and mathematical operations are verified against published vector datasets:
- NIST ACVP Known Answer Tests for standardized post-quantum algorithms.
- Project Wycheproof test vectors for edge cases and malformed parameter rejection.
- All vector files are tracked under `tests/vectors/`.
- Cross-verified against reference implementations to ensure zero divergence in serialized outputs.
- SHA-256 digests of all test vectors are verified prior to execution to guard against vector corruption.
- Intermediate round variables and state matrices are validated against step-by-step trace dumps.
- Regression tests execute across every supported platform matrix on every pull request.
- Edge case corpuses test zero-length payloads, all-ones matrices, and extreme prime field coordinates.

---

## Not Covered

The following operational characteristics are outside software unit test scope:
- **Physical Side-Channel Analysis:** Differential power analysis (DPA) and electromagnetic radiation leakage on custom embedded hardware are not covered by unit tests.
- **OS Kernel Compromise:** Fault injection or memory dumping by a compromised root kernel is not defended against at user application tier.
- **Cold Boot Attacks:** Direct physical memory extraction on non-encrypted RAM chips is outside the threat model of this library.
- **Hardware Fault Injection:** Rowhammer attacks and clock glitching vulnerabilities require dedicated silicon countermeasures and are out of scope.
- **Speculative Execution Flaws:** Transient CPU speculation leaks (Spectre/Meltdown variants) must be mitigated at microcode and OS level.
- **Subverted Hardware CSPRNG:** If the underlying CPU random number generator produces backdoored entropy, software primitives cannot compensate.
- **Physical Probing:** Direct microscopic circuit probing on bare silicon dies is outside software security boundaries.
