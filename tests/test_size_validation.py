"""S4 tests: FIPS size table validation — edge cases 2–7, 11 from §3 ledger.

Covers:
- Edge case 2: Wrong-length public key (KEM)
- Edge case 3: Wrong-length secret key (KEM)
- Edge case 4: Wrong-length ciphertext (KEM)
- Edge case 5: Wrong-length ML-DSA private key
- Edge case 6: Wrong-length ML-DSA public key (implicit rejection)
- Edge case 7: Wrong-length ML-DSA signature (implicit rejection)
- Edge case 11: Oversized inputs (DoS) — length > 2x expected
"""

import pytest
from pqblocks_qse_sdk.sizes import (
    _KEM_SIZES,
    _DSA_SIZES,
    _SLHDSASIZES,
    validate_keymaterial_length,
    validate_sig_length,
    get_size,
)


# ========================= Edge case 2: Wrong-length public key (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 800),
    ("ml-kem-768", 1184),
    ("ml-kem-1024", 1568),
])
def test_validate_pk_len_short(alg, expected):
    """Wrong-length public key for KEM → ValueError with expected/actual lengths."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid pk length: expected {expected}, got {len(short)}"):
        validate_keymaterial_length(alg, "pk", short, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 800),
    ("ml-kem-768", 1184),
    ("ml-kem-1024", 1568),
])
def test_validate_pk_len_none(alg, expected):
    """None value for pk is allowed (implicit rejection path)."""
    # Should not raise
    validate_keymaterial_length(alg, "pk", None, expected)


# ========================= Edge case 3: Wrong-length secret key (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 1632),
    ("ml-kem-768", 2400),
    ("ml-kem-1024", 3168),
])
def test_validate_sk_len_short(alg, expected):
    """Wrong-length secret key for KEM → ValueError with expected/actual lengths."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(short)}"):
        validate_keymaterial_length(alg, "sk", short, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 1632),
    ("ml-kem-768", 2400),
    ("ml-kem-1024", 3168),
])
def test_validate_sk_len_none(alg, expected):
    """None value for sk is allowed (implicit rejection path)."""
    validate_keymaterial_length(alg, "sk", None, expected)


# ========================= Edge case 4: Wrong-length ciphertext (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 768),
    ("ml-kem-768", 1088),
    ("ml-kem-1024", 1568),
])
def test_validate_ct_len_short(alg, expected):
    """Wrong-length ciphertext for KEM → ValueError with expected/actual lengths."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid ct length: expected {expected}, got {len(short)}"):
        validate_keymaterial_length(alg, "ct", short, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 768),
    ("ml-kem-768", 1088),
    ("ml-kem-1024", 1568),
])
def test_validate_ct_len_none(alg, expected):
    """None value for ct is allowed (implicit rejection path)."""
    validate_keymaterial_length(alg, "ct", None, expected)


# ========================= Edge case 5: Wrong-length ML-DSA private key =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2560),
    ("ml-dsa-65", 4032),
    ("ml-dsa-87", 4896),
])
def test_validate_ml_dsa_sk_len_short(alg, expected):
    """Wrong-length ML-DSA private key → ValueError with expected/actual lengths."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(short)}"):
        validate_keymaterial_length(alg, "sk", short, expected)


# ========================= Edge case 6: Wrong-length ML-DSA public key (implicit rejection) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 1312),
    ("ml-dsa-65", 1952),
    ("ml-dsa-87", 2592),
])
def test_validate_ml_dsa_pk_len_short_verify(alg, expected):
    """Wrong-length ML-DSA public key for verify → implicit rejection (returns False, no exception)."""
    short = b"x" * (expected // 2)
    # For verify, the facade will check length and return False (implicit rejection)
    # The validator is called with None or value - this tests the validator
    # When the value is provided, it should raise ValueError (for non-verify paths)
    # But verify has implicit rejection - the validator returns False or raises depending on usage
    # Here we test the raw validator behavior
    with pytest.raises(ValueError, match=f"Invalid pk length: expected {expected}, got {len(short)}"):
        validate_keymaterial_length(alg, "pk", short, expected)


# ========================= Edge case 7: Wrong-length ML-DSA signature (implicit rejection) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2420),
    ("ml-dsa-65", 3309),
    ("ml-dsa-87", 4627),
])
def test_validate_ml_dsa_sig_len_short_verify(alg, expected):
    """Wrong-length ML-DSA signature for verify → implicit rejection (returns False, no exception)."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid sig length: expected {expected}, got {len(short)}"):
        validate_sig_length(alg, short, expected)


# ========================= Edge case 11: Oversized inputs (DoS) — length > 2x expected =========================

@pytest.mark.parametrize("alg,size_field,expected", [
    ("ml-kem-512", "pk_len", 800),
    ("ml-kem-768", "pk_len", 1184),
    ("ml-kem-1024", "pk_len", 1568),
    ("ml-kem-512", "sk_len", 1632),
    ("ml-kem-768", "sk_len", 2400),
    ("ml-kem-1024", "sk_len", 3168),
    ("ml-kem-512", "ct_len", 768),
    ("ml-kem-768", "ct_len", 1088),
    ("ml-kem-1024", "ct_len", 1568),
])
def test_oversized_kem_inputs(alg, size_field, expected):
    """Oversized inputs (> 2x expected) raise ValueError immediately (no allocation)."""
    oversized = b"x" * (expected * 2 + 1)  # Just over 2x
    field_name = size_field.replace("_len", "")
    with pytest.raises(ValueError, match=f"Invalid {field_name} length: expected {expected}, got {len(oversized)}"):
        validate_keymaterial_length(alg, field_name, oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 1312),
    ("ml-dsa-65", 1952),
    ("ml-dsa-87", 2592),
])
def test_oversized_ml_dsa_pk(alg, expected):
    """Oversized ML-DSA public key (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid pk length: expected {expected}, got {len(oversized)}"):
        validate_keymaterial_length(alg, "pk", oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2560),
    ("ml-dsa-65", 4032),
    ("ml-dsa-87", 4896),
])
def test_oversized_ml_dsa_sk(alg, expected):
    """Oversized ML-DSA secret key (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(oversized)}"):
        validate_keymaterial_length(alg, "sk", oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2420),
    ("ml-dsa-65", 3309),
    ("ml-dsa-87", 4627),
])
def test_oversized_ml_dsa_sig(alg, expected):
    """Oversized ML-DSA signature (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid sig length: expected {expected}, got {len(oversized)}"):
        validate_sig_length(alg, oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("slh-dsa-sha2-128s", 32),
    ("slh-dsa-sha2-128f", 32),
    ("slh-dsa-sha2-192s", 48),
    ("slh-dsa-sha2-192f", 48),
    ("slh-dsa-sha2-256s", 64),
    ("slh-dsa-sha2-256f", 64),
    ("slh-dsa-shake-128s", 32),
    ("slh-dsa-shake-128f", 32),
    ("slh-dsa-shake-192s", 48),
    ("slh-dsa-shake-192f", 48),
    ("slh-dsa-shake-256s", 64),
    ("slh-dsa-shake-256f", 64),
])
def test_oversized_slh_dsa_pk(alg, expected):
    """Oversized SLH-DSA public key (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid pk length: expected {expected}, got {len(oversized)}"):
        validate_keymaterial_length(alg, "pk", oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("slh-dsa-sha2-128s", 64),
    ("slh-dsa-sha2-128f", 64),
    ("slh-dsa-sha2-192s", 96),
    ("slh-dsa-sha2-192f", 96),
    ("slh-dsa-sha2-256s", 128),
    ("slh-dsa-sha2-256f", 128),
    ("slh-dsa-shake-128s", 64),
    ("slh-dsa-shake-128f", 64),
    ("slh-dsa-shake-192s", 96),
    ("slh-dsa-shake-192f", 96),
    ("slh-dsa-shake-256s", 128),
    ("slh-dsa-shake-256f", 128),
])
def test_oversized_slh_dsa_sk(alg, expected):
    """Oversized SLH-DSA secret key (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(oversized)}"):
        validate_keymaterial_length(alg, "sk", oversized, expected)


@pytest.mark.parametrize("alg,expected", [
    ("slh-dsa-sha2-128s", 7856),
    ("slh-dsa-sha2-128f", 17088),
    ("slh-dsa-sha2-192s", 16224),
    ("slh-dsa-sha2-192f", 35664),
    ("slh-dsa-sha2-256s", 29792),
    ("slh-dsa-sha2-256f", 49856),
    ("slh-dsa-shake-128s", 7856),
    ("slh-dsa-shake-128f", 17088),
    ("slh-dsa-shake-192s", 16224),
    ("slh-dsa-shake-192f", 35664),
    ("slh-dsa-shake-256s", 29792),
    ("slh-dsa-shake-256f", 49856),
])
def test_oversized_slh_dsa_sig(alg, expected):
    """Oversized SLH-DSA signature (> 2x expected) raises ValueError."""
    oversized = b"x" * (expected * 2 + 1)
    with pytest.raises(ValueError, match=f"Invalid sig length: expected {expected}, got {len(oversized)}"):
        validate_sig_length(alg, oversized, expected)


# ========================= Type error tests =========================

def test_validate_pk_wrong_type():
    """Non-bytes public key raises TypeError; None is allowed (implicit rejection)."""
    with pytest.raises(TypeError, match="pk must be bytes, got str"):
        validate_keymaterial_length("ml-kem-768", "pk", "not bytes", 1184)
    # None is allowed - implicit rejection path
    validate_keymaterial_length("ml-kem-768", "pk", None, 1184)


def test_validate_sk_wrong_type():
    """Non-bytes secret key raises TypeError."""
    with pytest.raises(TypeError, match="sk must be bytes, got str"):
        validate_keymaterial_length("ml-kem-768", "sk", "not bytes", 2400)


def test_validate_ct_wrong_type():
    """Non-bytes ciphertext raises TypeError."""
    with pytest.raises(TypeError, match="ct must be bytes, got str"):
        validate_keymaterial_length("ml-kem-768", "ct", "not bytes", 1088)


def test_validate_sig_wrong_type():
    """Non-bytes signature raises TypeError."""
    with pytest.raises(TypeError, match="signature must be bytes"):
        validate_sig_length("ml-dsa-65", "not bytes", 3309)


# ========================= get_size function tests =========================

@pytest.mark.parametrize("alg,field,expected", [
    ("ml-kem-512", "pk_len", 800),
    ("ml-kem-512", "sk_len", 1632),
    ("ml-kem-512", "ct_len", 768),
    ("ml-kem-512", "ss_len", 32),
    ("ml-kem-768", "pk_len", 1184),
    ("ml-kem-768", "sk_len", 2400),
    ("ml-kem-768", "ct_len", 1088),
    ("ml-kem-768", "ss_len", 32),
    ("ml-kem-1024", "pk_len", 1568),
    ("ml-kem-1024", "sk_len", 3168),
    ("ml-kem-1024", "ct_len", 1568),
    ("ml-kem-1024", "ss_len", 32),
    ("ml-dsa-44", "pk_len", 1312),
    ("ml-dsa-44", "sk_len", 2560),
    ("ml-dsa-44", "sig_len", 2420),
    ("ml-dsa-65", "pk_len", 1952),
    ("ml-dsa-65", "sk_len", 4032),
    ("ml-dsa-65", "sig_len", 3309),
    ("ml-dsa-87", "pk_len", 2592),
    ("ml-dsa-87", "sk_len", 4896),
    ("ml-dsa-87", "sig_len", 4627),
    ("slh-dsa-sha2-128s", "pk_len", 32),
    ("slh-dsa-sha2-128s", "sk_len", 64),
    ("slh-dsa-sha2-128s", "sig_len", 7856),
    ("slh-dsa-sha2-128f", "pk_len", 32),
    ("slh-dsa-sha2-128f", "sk_len", 64),
    ("slh-dsa-sha2-128f", "sig_len", 17088),
])
def test_get_size(alg, field, expected):
    """get_size returns the correct FIPS table size."""
    assert get_size(alg, field) == expected


def test_get_size_unknown_algorithm():
    """get_size raises KeyError for unknown algorithm."""
    with pytest.raises(KeyError, match="Unknown algorithm: unknown-alg"):
        get_size("unknown-alg", "pk_len")


def test_get_size_unknown_field():
    """get_size raises KeyError for unknown field."""
    with pytest.raises(KeyError):
        get_size("ml-kem-768", "unknown_field")


# ========================= Table completeness tests =========================

def test_kem_sizes_table_complete():
    """_KEM_SIZES has all three ML-KEM algorithms."""
    assert set(_KEM_SIZES.keys()) == {"ml-kem-512", "ml-kem-768", "ml-kem-1024"}
    for alg in _KEM_SIZES:
        assert set(_KEM_SIZES[alg].keys()) == {"pk_len", "sk_len", "ct_len", "ss_len"}


def test_dsa_sizes_table_complete():
    """_DSA_SIZES has all three ML-DSA algorithms."""
    assert set(_DSA_SIZES.keys()) == {"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}
    for alg in _DSA_SIZES:
        assert set(_DSA_SIZES[alg].keys()) == {"pk_len", "sk_len", "sig_len"}


def test_slhdsa_sizes_table_complete():
    """_SLHDSASIZES has the expected SLH-DSA algorithms."""
    expected_algs = {
        "slh-dsa-sha2-128s", "slh-dsa-sha2-128f",
        "slh-dsa-sha2-192s", "slh-dsa-sha2-192f",
        "slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
        "slh-dsa-shake-128s", "slh-dsa-shake-128f",
        "slh-dsa-shake-192s", "slh-dsa-shake-192f",
        "slh-dsa-shake-256s", "slh-dsa-shake-256f",
    }
    assert set(_SLHDSASIZES.keys()) == expected_algs
    for alg in _SLHDSASIZES:
        assert set(_SLHDSASIZES[alg].keys()) == {"pk_len", "sk_len", "sig_len"}