"""pqblocks-qse-sdk — pqblock post-quantum cryptography SDK.

This package composes FIPS 203 / FIPS 204 / FIPS 205 primitives from
maintained libraries (``pqcrypto`` and ``cryptography``), validates key
and message sizes against the standards tables, and adds SDK-layer
features (deterministic corpus generation, cross-language compatibility
matrix, static hardening scanner).

Public surface (scaffold, S1):

- ``keypair`` — unified keypair generation across ML-KEM / ML-DSA / SLH-DSA.
- ``encapsulate`` — ML-KEM encapsulation (KEM only).
- ``decapsulate`` — ML-KEM decapsulation (KEM only).
- ``sign`` — ML-DSA / SLH-DSA signature generation.
- ``verify`` — ML-DSA / SLH-DSA signature verification.
- ``corpus_generate`` — deterministic cross-language test-vector corpus.
- ``matrix_status`` — runtime cross-language compatibility matrix.
- ``harden_check_unsafe_api`` — static analysis for deprecated PQC API usage.
- ``status`` — SDK introspection: version, primitive libraries, FIPS table version.

No lattice or hash-based cryptography is reimplemented here; every primitive
call is delegated to a maintained library.
"""

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "keypair",
    "encapsulate",
    "decapsulate",
    "sign",
    "verify",
    "corpus_generate",
    "matrix_status",
    "harden_check_unsafe_api",
    "status",
]

# ---------------------------------------------------------------------------
# Re-exports
# ---------------------------------------------------------------------------
# The package exposes its public API across unified namespaces:
# keypair, encapsulate, decapsulate, sign, verify, corpus_generate,
# matrix_status, harden_check_unsafe_api, status.


def _lazy_not_implemented(name: str):
    def _fn(*_args, **_kwargs):
        raise NotImplementedError(
            f"{name} is not available"
        )
    _fn.__name__ = name
    _fn.__qualname__ = name
    _fn.__doc__ = f"Placeholder for {name}."
    return _fn


try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.kem import keypair, encapsulate, decapsulate  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S1
    keypair = _lazy_not_implemented("keypair")
    encapsulate = _lazy_not_implemented("encapsulate")
    decapsulate = _lazy_not_implemented("decapsulate")

try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.corpus import corpus_generate  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S1
    corpus_generate = _lazy_not_implemented("corpus_generate")

try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.matrix import matrix_status  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S1
    matrix_status = _lazy_not_implemented("matrix_status")

try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.harden import harden_check_unsafe_api  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S1
    harden_check_unsafe_api = _lazy_not_implemented("harden_check_unsafe_api")

try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.meta import status  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S1
    status = _lazy_not_implemented("status")

# S3: sign/verify façade (added per fix list in Check 3 (correctness) report).
#
# NOTE: only ``sign`` and ``verify`` are re-exported here. ``keypair`` is
# deliberately NOT re-exported from ``pqblocks-qse-sdk.sign``: the unified entry point
# is ``pqblocks-qse-sdk.kem.keypair`` (spec §1.2), which itself dispatches signature
# algorithm names to ``pqblocks-qse-sdk.sign.keypair``. Re-exporting the signature-side
# ``keypair`` here would shadow the unified one and make
# ``pqblocks-qse-sdk.keypair("ml-kem-768")`` raise "Unsupported algorithm".
#
# NOTE: binding the name ``sign`` here shadows the *submodule* attribute
# ``pqblocks-qse-sdk.sign`` on the package object. Code that needs the module itself
# must use ``import pqblocks-qse-sdk.sign as sign_module`` / ``sys.modules["pqblocks-qse-sdk.sign"]``.
try:  # pragma: no cover - exercised implicitly by every SDK use
    from pqblocks_qse_sdk.sign import sign, verify  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - normal state during S3 development
    sign = _lazy_not_implemented("sign")
    verify = _lazy_not_implemented("verify")
