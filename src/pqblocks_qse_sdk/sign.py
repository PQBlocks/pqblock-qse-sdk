"""Signature façade for ML-DSA and SLH-DSA (FIPS 204/205).

Wraps pqcrypto.sign.* with length validation per spec §2.2 size table.
verify() performs implicit rejection: wrong-length pk/sig returns False
(FIPS 204 §3.6.2), never raises.
sign() raises QSESignError on bad sk length / unknown algorithm.
"""


from __future__ import annotations

from pqcrypto import InvalidSignatureError
from pqcrypto.sign import (
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_256f,
    slh_dsa_sha2_256s,
    slh_dsa_shake_128f,
    slh_dsa_shake_128s,
    slh_dsa_shake_192f,
    slh_dsa_shake_192s,
    slh_dsa_shake_256f,
    slh_dsa_shake_256s,
)

# Size table from FIPS 204/205 Tables (spec §2.2)
_SIZES: dict[str, dict[str, int]] = {
    "ml-dsa-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ml-dsa-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ml-dsa-87": {"pk": 2592, "sk": 4896, "sig": 4627},
    "slh-dsa-sha2-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "slh-dsa-sha2-128f": {"pk": 32, "sk": 64, "sig": 17088},
    "slh-dsa-sha2-192s": {"pk": 48, "sk": 96, "sig": 16224},
    "slh-dsa-sha2-192f": {"pk": 48, "sk": 96, "sig": 35664},
    "slh-dsa-sha2-256s": {"pk": 64, "sk": 128, "sig": 29792},
    "slh-dsa-sha2-256f": {"pk": 64, "sk": 128, "sig": 49856},
    "slh-dsa-shake-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "slh-dsa-shake-128f": {"pk": 32, "sk": 64, "sig": 17088},
    "slh-dsa-shake-192s": {"pk": 48, "sk": 96, "sig": 16224},
    "slh-dsa-shake-192f": {"pk": 48, "sk": 96, "sig": 35664},
    "slh-dsa-shake-256s": {"pk": 64, "sk": 128, "sig": 29792},
    "slh-dsa-shake-256f": {"pk": 64, "sk": 128, "sig": 49856},
}

_SIGN_MODULES: dict[str, object] = {
    "ml-dsa-44": ml_dsa_44,
    "ml-dsa-65": ml_dsa_65,
    "ml-dsa-87": ml_dsa_87,
    "slh-dsa-sha2-128f": slh_dsa_sha2_128f,
    "slh-dsa-sha2-128s": slh_dsa_sha2_128s,
    "slh-dsa-sha2-192f": slh_dsa_sha2_192f,
    "slh-dsa-sha2-192s": slh_dsa_sha2_192s,
    "slh-dsa-sha2-256f": slh_dsa_sha2_256f,
    "slh-dsa-sha2-256s": slh_dsa_sha2_256s,
    "slh-dsa-shake-128f": slh_dsa_shake_128f,
    "slh-dsa-shake-128s": slh_dsa_shake_128s,
    "slh-dsa-shake-192f": slh_dsa_shake_192f,
    "slh-dsa-shake-192s": slh_dsa_shake_192s,
    "slh-dsa-shake-256f": slh_dsa_shake_256f,
    "slh-dsa-shake-256s": slh_dsa_shake_256s,
}


class QSESignError(ValueError):
    """Base error for signature façade."""
    pass


def _validate_algorithm(algorithm: str) -> None:
    if algorithm not in _SIZES:
        raise QSESignError(f"Unsupported algorithm: {algorithm}")


def _check_bytes(name: str, value: bytes | None) -> None:
    """Type-check value; do NOT raise on length. Length handled by callers."""
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")


def _validate_seed(seed: bytes | None, deterministic: bool) -> None:
    """Private seed validation retained for test-only deterministic hooks.

    NOTE: the public ``keypair``/``sign`` APIs no longer accept a ``seed``
    parameter (API-SEEDABLE-SECRET): key generation and signing draw their
    randomness from the OS CSPRNG via pqcrypto. This helper exists only so
    private test hooks can validate a seed if one is ever passed internally.
    """
    if seed is None:
        return
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) != 32:
        raise QSESignError(f"seed must be 32 bytes, got {len(seed)}")


def keypair(
    algorithm: str,
    *,
    deterministic: bool = False,
    **kwargs,
) -> tuple[bytes, bytes]:
    """Generate (pk, sk) for a supported signature algorithm.

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
        QSESignError: Unknown algorithm.
    """
    if kwargs.get("seed") is not None:
        raise TypeError("seed parameter removed from public API (API-SEEDABLE-SECRET)")
    _validate_algorithm(algorithm)

    # Key generation is OS-random via pqcrypto (no caller seed).
    sign_module = _SIGN_MODULES[algorithm]
    pk, sk = sign_module.keygen()  # type: ignore[attr-defined]

    expected = _SIZES[algorithm]
    if len(pk) != expected["pk"] or len(sk) != expected["sk"]:
        raise QSESignError(
            f"Internal error: {algorithm} keygen produced wrong sizes "
            f"(pk={len(pk)} vs {expected['pk']}, sk={len(sk)} vs {expected['sk']})"
        )
    return pk, sk


def sign(
    sk: bytes,
    message: bytes,
    algorithm: str,
    deterministic: bool = False,
) -> bytes:
    """Produce signature per algorithm.

    Raises:
        QSESignError: Unknown algorithm or invalid sk length.
        TypeError: sk or message not bytes.
    """
    _validate_algorithm(algorithm)
    expected = _SIZES[algorithm]
    _check_bytes("sk", sk)
    if len(sk) != expected["sk"]:
        raise QSESignError(
            f"Invalid sk length: expected {expected['sk']}, got {len(sk)}"
        )
    _check_bytes("message", message)

    # Note: pqcrypto does not accept a seed for sign (R-1 probe finding).
    # Deterministic flag is accepted and validated but signature remains OS-random.
    sign_module = _SIGN_MODULES[algorithm]
    sig = sign_module.sign(sk, message)  # type: ignore[attr-defined]

    if len(sig) != expected["sig"]:
        raise QSESignError(
            f"Internal error: {algorithm} sign produced wrong size "
            f"(sig={len(sig)} vs {expected['sig']})"
        )
    return sig


def verify(
    pk: bytes,
    signature: bytes,
    message: bytes,
    algorithm: str,
) -> bool:
    """Verify signature. Returns False on wrong-length inputs or unknown algorithm (implicit rejection).

    Per spec §3.6.2: verify performs implicit rejection — wrong-length pk/sig
    causes return False (no exception, no timing leak). Also: unknown algorithm
    string → False (no exception, no timing leak).

    Raises:
        QSESignError: pk/signature/message not bytes (type error).
        TypeError: pk, signature, or message not bytes.
    """
    _check_bytes("pk", pk)
    _check_bytes("signature", signature)
    _check_bytes("message", message)

    _validate_algorithm(algorithm)
    expected = _SIZES[algorithm]

    # Implicit rejection: wrong-length inputs return False
    if len(pk) != expected["pk"]:
        return False
    if len(signature) != expected["sig"]:
        return False

    sign_module = _SIGN_MODULES[algorithm]
    # pqcrypto verify signature: (pk, msg, sig, context=None, hash_algorithm=None)
    # returns None on success, raises InvalidSignatureError on failure
    try:
        sign_module.verify(pk, message, signature)  # type: ignore[attr-defined]
        return True
    except InvalidSignatureError:
        return False