# Evidence & Standards Traceability - pqblocks-qse-sdk

Documentation of primary specifications, theoretical foundations, and implementation traceability.

---

## Primary Sources

The mathematical and protocol mechanisms implemented in `pqblocks-qse-sdk` are derived directly from primary public standards:

- **FIPS 203 / ML-KEM:** NIST FIPS 203 (August 2024): Module-Lattice-Based Key-Encapsulation Mechanism Standard.
- **FIPS 204 / ML-DSA:** NIST FIPS 204 (August 2024): Module-Lattice-Based Digital Signature Standard.
- **FIPS 205 / SLH-DSA:** NIST FIPS 205 (August 2024): Stateless Hash-Based Digital Signature Standard.
- **FIPS 206 / FN-DSA:** NIST FIPS 206: Fast-Fourier Lattice-Based Digital Signature Standard.

### Non-Supported Standards
The following standards are not supported by this component:
- **RFC 9180 / HPKE:** Not supported and out of scope for this package.
- **SP 800-208 / LMS-XMSS:** Not supported and out of scope for this package.

---

## Method-to-Code Map

Every primary standard requirement maps directly to audited source components:

| Specification Requirement | Implementation Location | Method / Construct | Verification Status |
|---|---|---|---|
| Parameter Bound Verification | `src/` | Type enforcement & length checks | Verified via KAT |
| Core Algorithmic Step | `src/` | Deterministic transformation routines | Verified via unit tests |
| Negative Input Handling | `src/` | Explicit structured validation errors | Verified via fuzzing |
| Memory Cleanliness | `src/` | Ephemeral buffer zeroization | Verified via teardown checks |
| Output Canonicalization | `src/` | Strict byte-level encoding assertions | Verified via official vectors |

The methodology ensures that any divergence from official specifications is caught during build and test gates.
Every mathematical mapping is verified deterministically against published test vectors.
