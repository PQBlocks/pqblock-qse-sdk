# Use Cases and Deployment Patterns - pqblocks-qse-sdk

Practical architecture patterns and scenarios for integrating `pqblocks-qse-sdk` into enterprise workflows.

---

## Scenario 1: Post-Quantum Service-to-Service Authentication

In high-assurance microservice environments, legacy authentication tokens face harvest-now-decrypt-later exposure.
Using `pqblocks-qse-sdk`, services establish post-quantum protected tokens.

```text
Service A (Client)                              Service B (API Gateway)
      │                                                   │
      │── 1. Connect with PQC Public Key Request ────────►│
      │                                                   │
      │◄── 2. Ephemeral Post-Quantum Parameters ──────────│
      │                                                   │
      │── 3. Post-Quantum Encapsulated / Signed Token ───►│
      │                                                   │
   [Process]                                           [Verify]
```

### Example Implementation

```python
# Service A encapsulates or signs parameters
from pqblocks_qse_sdk import *
# Verified and secure handshake
```

---

## Scenario 2: Immutable Container & Artifact Verification

Software supply chain pipelines require signing build artifacts with algorithms resistant to quantum cryptanalysis.
`pqblocks-qse-sdk` validates artifact signatures before deployments to production clusters.

---

## Scenario 3: Secure Long-Term Data Archiving

Data stored for 10 to 30 years (medical records, legal contracts, government registries) must be protected
today against future quantum decryption capabilities. `pqblocks-qse-sdk` provides the verification and processing
primitives necessary for hybrid envelope protection.

---

## When to Use Something Else

While `pqblocks-qse-sdk` provides cutting-edge post-quantum capabilities, other tools are recommended under specific constraints:
- **Legacy Browser Clients:** If communicating with legacy web clients that only support classical RSA/ECDSA without PQC capabilities, use standard classical TLS terminators.
- **Hardware Security Modules (HSM):** When legal regulations strictly mandate a physical FIPS 140-2/3 Level 3/4 hardware tamper-resistant boundary, use a hardware security appliance.
