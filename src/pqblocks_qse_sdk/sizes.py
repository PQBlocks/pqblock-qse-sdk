"""FIPS 203/204/205 size tables and validators for pqblocks-qse-sdk SDK.

This module provides the canonical size table (public key, secret key, ciphertext,
shared secret, and signature lengths) derived from the FIPS 203/204/205 standards,
and validators that raise ``ValueError`` when key/ciphertext/signature lengths do
not match the expected values for the given algorithm.
"""

# FIPS 203 Table 3: ML-KEM size parameters (bytes)
_KEM_SIZES: dict[str, dict[str, int]] = {
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

# FIPS 204 Table 2: ML-DSA size parameters (bytes)
_DSA_SIZES: dict[str, dict[str, int]] = {
    "ml-dsa-44": {
        "pk_len": 1312,
        "sk_len": 2560,
        "sig_len": 2420,
    },
    "ml-dsa-65": {
        "pk_len": 1952,
        "sk_len": 4032,
        "sig_len": 3309,
    },
    "ml-dsa-87": {
        "pk_len": 2592,
        "sk_len": 4896,
        "sig_len": 4627,
    },
}

# FIPS 205 Table 2: SLH-DSA size parameters (bytes)
_SLHDSASIZES: dict[str, dict[str, int]] = {
    "slh-dsa-sha2-128s": {
        "pk_len": 32,
        "sk_len": 64,
        "sig_len": 7856,
    },
    "slh-dsa-sha2-128f": {
        "pk_len": 32,
        "sk_len": 64,
        "sig_len": 17088,  # FIPS 205 Table 2
    },
    "slh-dsa-sha2-192s": {
        "pk_len": 48,
        "sk_len": 96,
        "sig_len": 16224,  # FIPS 205 Table 2
    },
    "slh-dsa-sha2-192f": {
        "pk_len": 48,
        "sk_len": 96,
        "sig_len": 35664,  # FIPS 205 Table 2
    },
    "slh-dsa-sha2-256s": {
        "pk_len": 64,
        "sk_len": 128,
        "sig_len": 29792,  # FIPS 205 Table 2
    },
    "slh-dsa-sha2-256f": {
        "pk_len": 64,
        "sk_len": 128,
        "sig_len": 49856,  # FIPS 205 Table 2
    },
    "slh-dsa-shake-128s": {
        "pk_len": 32,
        "sk_len": 64,
        "sig_len": 7856,
    },
    "slh-dsa-shake-128f": {
        "pk_len": 32,
        "sk_len": 64,
        "sig_len": 17088,
    },
    "slh-dsa-shake-192s": {
        "pk_len": 48,
        "sk_len": 96,
        "sig_len": 16224,
    },
    "slh-dsa-shake-192f": {
        "pk_len": 48,
        "sk_len": 96,
        "sig_len": 35664,
    },
    "slh-dsa-shake-256s": {
        "pk_len": 64,
        "sk_len": 128,
        "sig_len": 29792,
    },
    "slh-dsa-shake-256f": {
        "pk_len": 64,
        "sk_len": 128,
        "sig_len": 49856,
    },
}


def validate_keymaterial_length(algorithm: str, name: str, value: bytes | None, expected_len: int) -> None:
    """Validate that *value* has the expected length for *algorithm*.

    Raises ``ValueError`` if the length does not match; the error message
    follows the pattern ``"Invalid {name} length: expected {expected_len}, got {actual_len}"``.

    Args:
        algorithm: The algorithm identifier (e.g. ``"ml-kem-768"``).
        name: The material name (e.g. ``"pk"``, ``"sk"``, ``"ct"``, ``"sig"``).
        value: The byte sequence to validate; may be ``None`` for implicit-rejection paths.
        expected_len: The FIPS-standard length in bytes expected for this algorithm.
    """
    if value is None:
        return  # implicit rejection (e.g. verify with short pk) does not raise
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if len(value) != expected_len:
        raise ValueError(f"Invalid {name} length: expected {expected_len}, got {len(value)}")


def validate_sig_length(algorithm: str, sig: bytes | None, expected_len: int) -> None:
    """Validate signature length per FIPS table for the given algorithm.

    Raises ``ValueError`` if the signature length does not match; follows the same
    error-message convention as :func:`validate_keymaterial_length`.
    """
    if sig is None:
        return
    if not isinstance(sig, bytes):
        raise TypeError("signature must be bytes")
    if len(sig) != expected_len:
        raise ValueError(f"Invalid sig length: expected {expected_len}, got {len(sig)}")


def get_size(algorithm: str, field: str) -> int:
    """Return the FIPS table size for *field* of *algorithm*.

    Supported *field* values: ``"pk_len"``, ``"sk_len"``, ``"ct_len"``,
    ``"ss_len"``, ``"sig_len"``.  Raises ``KeyError`` if the algorithm or
    field is not in the table.
    """
    if algorithm in _KEM_SIZES:
        return _KEM_SIZES[algorithm][field]
    if algorithm in _DSA_SIZES:
        return _DSA_SIZES[algorithm][field]
    if algorithm in _SLHDSASIZES:
        return _SLHDSASIZES[algorithm][field]
    raise KeyError(f"Unknown algorithm: {algorithm}")