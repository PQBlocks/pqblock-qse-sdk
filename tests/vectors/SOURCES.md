# Cryptographic Test Vector Sources

All test vectors in this directory originate from official standards bodies and reference implementations:

1. **NIST ACVP ML-KEM Vectors (`acvp/ML-KEM-encapDecap-FIPS203.json`)**:
   - Origin: NIST Automated Cryptographic Validation Program (ACVP) reference server (`ACVP-Server/gen-val/json-files/ML-KEM-encapDecap-FIPS203`).
   - Standard: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard).
   - Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
   - Purpose: Validates decapsulation correctness and encapsulation ciphertext consistency against official NIST KAT projections.

2. **NIST ACVP ML-DSA Vectors (`acvp/ML-DSA-sigVer-FIPS204.json`)**:
   - Origin: NIST ACVP reference server (`ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204`).
   - Standard: NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard).
   - Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87.
   - Purpose: Validates signature verification and negative test case rejection against official NIST ACVP prompt and response sets.

3. **NIST ACVP SLH-DSA Vectors (`acvp/SLH-DSA-sigVer-FIPS205.json`)**:
   - Origin: NIST ACVP reference server (`ACVP-Server/gen-val/json-files/SLH-DSA-sigVer-FIPS205`).
   - Standard: NIST FIPS 205 (Stateless Hash-Based Digital Signature Standard).
   - Parameter sets: SLH-DSA-SHA2-128s/f, 192s/f, 256s/f and SLH-DSA-SHAKE-128s/f, 192s/f, 256s/f.
   - Purpose: Validates stateless hash-based signature verification and parameter bounds.

4. **Wycheproof ML-DSA Vectors (`wycheproof/mldsa_65_verify_test.json`)**:
   - Origin: Project Wycheproof (Google / C2SP).
   - Standard: NIST FIPS 204.
   - Parameter sets: ML-DSA-65.
   - Purpose: Negative test cases, malformed signatures, modified messages, edge case rejections, and context binding.
