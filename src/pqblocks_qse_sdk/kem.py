from __future__ import annotations

from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

# Size table from FIPS 203 Table 3 (spec §2.2)
_SIZES: dict[str, dict[str, int]] = {
    "ml-kem-512": {
        "pk_len": 800,
        "sk_len": 1632,
        "ct_len": 768,
        "ss_len": 32,
    },
    "ml-kem-768": {
        "pk_len": 1184,
        "sk_len": 2400,
        "ct_len": 1088,
        "ss_len": 32,
    },
    "ml-kem-1024": {
        "pk_len": 1568,
        "sk_len": 3168,
        "ct_len": 1568,
        "ss_len": 32,
    },
}

# Signature algorithms served by the sign/verify façade (S3).
_SIGN_ALGORITHMS: list[str] = [
    "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
    "slh-dsa-sha2-128s", "slh-dsa-sha2-128f",
    "slh-dsa-sha2-192s", "slh-dsa-sha2-192f",
    "slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
    "slh-dsa-shake-128s", "slh-dsa-shake-128f",
    "slh-dsa-shake-192s", "slh-dsa-shake-192f",
    "slh-dsa-shake-256s", "slh-dsa-shake-256f",
]

_KEM_MODULES = {
    "ml-kem-512": ml_kem_512,
    "ml-kem-768": ml_kem_768,
    "ml-kem-1024": ml_kem_1024,
}


class QSEKemError(ValueError):
    """Base error for KEM façade."""
    pass


def _validate_algorithm(algorithm: str) -> None:
    if algorithm not in _SIZES and algorithm not in _SIGN_ALGORITHMS:
        raise QSEKemError(f"Unsupported algorithm: {algorithm}")


def _validate_bytes(name: str, value: bytes | None, expected_len: int) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(value) != expected_len:
        raise QSEKemError(f"Invalid {name} length: expected {expected_len}, got {len(value)}")


def _validate_seed(seed: bytes | None, deterministic: bool = False) -> None:
    if deterministic:
        if seed is None:
            raise ValueError("seed must be provided when deterministic=True")
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    elif seed is not None:
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")


def keypair(
    algorithm: str,
    *,
    deterministic: bool = False,
    **kwargs,
) -> tuple[bytes, bytes]:
    """Generate (pk, sk) for a supported KEM or signature algorithm.

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
        TypeError: seed not bytes.
    """
    seed = kwargs.get("seed")
    # Signature algorithms are served by the signature façade (S3).
    if algorithm in _SIGN_ALGORITHMS:
        from pqblocks_qse_sdk.sign import keypair as _sign_keypair
        return _sign_keypair(algorithm, deterministic=deterministic)

    _validate_algorithm(algorithm)
    _validate_seed(seed, deterministic)

    # Key generation is OS-random via pqcrypto (no caller seed).
    kem = _KEM_MODULES[algorithm]
    pk, sk = kem.keygen()

    # Sanity check sizes match FIPS 203
    expected = _SIZES[algorithm]
    if len(pk) != expected["pk_len"] or len(sk) != expected["sk_len"]:
        raise QSEKemError(
            f"Internal error: {algorithm} keygen produced wrong sizes "
            f"(pk={len(pk)} vs {expected['pk_len']}, sk={len(sk)} vs {expected['sk_len']})"
        )
    return pk, sk


def encapsulate(
    pk: bytes,
    algorithm: str,
    **kwargs,
) -> tuple[bytes, bytes]:
    """KEM encapsulation: (ciphertext, shared_secret).

    Args:
        pk: Public key bytes (must match algorithm's pk_len).
        algorithm: One of "ml-kem-512", "ml-kem-768", "ml-kem-1024".
        **kwargs: Optional keyword arguments (e.g. seed).

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes.

    Raises:
        QSEKemError: Unknown algorithm or invalid pk length.
        TypeError: pk or seed not bytes.
        ValueError: Invalid seed length.
    """
    seed = kwargs.get("seed")
    _validate_algorithm(algorithm)
    expected = _SIZES[algorithm]
    _validate_bytes("pk", pk, expected["pk_len"])
    _validate_seed(seed, deterministic=False)

    kem = _KEM_MODULES[algorithm]
    ct, ss = kem.encaps(pk)

    if len(ct) != expected["ct_len"] or len(ss) != expected["ss_len"]:
        raise QSEKemError(
            f"Internal error: {algorithm} encaps produced wrong sizes "
            f"(ct={len(ct)} vs {expected['ct_len']}, ss={len(ss)} vs {expected['ss_len']})"
        )
    return ct, ss


def decapsulate(
    sk: bytes,
    ct: bytes,
    algorithm: str,
    **kwargs,
) -> bytes:
    """KEM decapsulation -> 32-byte shared secret.

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
        ValueError: Invalid seed length.
    """
    seed = kwargs.get("seed")
    _validate_algorithm(algorithm)
    expected = _SIZES[algorithm]
    _validate_bytes("sk", sk, expected["sk_len"])
    _validate_bytes("ct", ct, expected["ct_len"])
    _validate_seed(seed, deterministic=False)

    kem = _KEM_MODULES[algorithm]
    ss = kem.decaps(sk, ct)

    if len(ss) != expected["ss_len"]:
        raise QSEKemError(
            f"Internal error: {algorithm} decaps produced wrong size "
            f"(ss={len(ss)} vs {expected['ss_len']})"
        )
    return ss