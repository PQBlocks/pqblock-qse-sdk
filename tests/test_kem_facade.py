"""S2 tests: KEM façade — keypair, encapsulate, decapsulate with length validation.

Covers:
- Happy path for ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Edge cases 2, 3, 4, 11 from §3 ledger (wrong-length pk/sk/ct, oversized)
- Edge case 1 (unknown algorithm)
- Deterministic seed parameter acceptance (per §2.3, not actually used for reproducible keygen)
- Round-trip: decapsulate(sk, encapsulate(pk)[0]) == ss
"""

import pytest
from pqblocks_qse_sdk import keypair, encapsulate, decapsulate


# ========================= Happy path =========================

@pytest.mark.parametrize("alg", ["ml-kem-512", "ml-kem-768", "ml-kem-1024"])
def test_keypair_happy(alg):
    pk, sk = keypair(alg)
    # Check sizes match FIPS 203 Table 3
    if alg == "ml-kem-512":
        assert len(pk) == 800
        assert len(sk) == 1632
    elif alg == "ml-kem-768":
        assert len(pk) == 1184
        assert len(sk) == 2400
    elif alg == "ml-kem-1024":
        assert len(pk) == 1568
        assert len(sk) == 3168


@pytest.mark.parametrize("alg", ["ml-kem-512", "ml-kem-768", "ml-kem-1024"])
def test_encapsulate_decapsulate_roundtrip(alg):
    pk, sk = keypair(alg)
    ct, ss = encapsulate(pk, alg)
    ss2 = decapsulate(sk, ct, alg)
    assert ss == ss2
    assert len(ss) == 32
    # Check ciphertext size
    if alg == "ml-kem-512":
        assert len(ct) == 768
    elif alg == "ml-kem-768":
        assert len(ct) == 1088
    elif alg == "ml-kem-1024":
        assert len(ct) == 1568


# ========================= Edge case 1: Unknown algorithm =========================

def test_keypair_unknown_algorithm():
    with pytest.raises(ValueError, match="Unsupported algorithm: ml-kem-999"):
        keypair("ml-kem-999")


def test_encapsulate_unknown_algorithm():
    pk = b"x" * 1184
    with pytest.raises(ValueError, match="Unsupported algorithm: ml-kem-999"):
        encapsulate(pk, "ml-kem-999")


def test_decapsulate_unknown_algorithm():
    sk = b"x" * 2400
    ct = b"x" * 1088
    with pytest.raises(ValueError, match="Unsupported algorithm: ml-kem-999"):
        decapsulate(sk, ct, "ml-kem-999")


# ========================= Edge case 2: Wrong-length public key (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 800),
    ("ml-kem-768", 1184),
    ("ml-kem-1024", 1568),
])
def test_encapsulate_pk_len(alg, expected):
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid pk length: expected {expected}, got {len(short)}"):
        encapsulate(short, alg)


# ========================= Edge case 3: Wrong-length secret key (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 1632),
    ("ml-kem-768", 2400),
    ("ml-kem-1024", 3168),
])
def test_decapsulate_sk_len(alg, expected):
    short = b"x" * (expected // 2)
    ct = b"x" * (768 if alg == "ml-kem-512" else 1088 if alg == "ml-kem-768" else 1568)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(short)}"):
        decapsulate(short, ct, alg)


# ========================= Edge case 4: Wrong-length ciphertext (KEM) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-kem-512", 768),
    ("ml-kem-768", 1088),
    ("ml-kem-1024", 1568),
])
def test_decapsulate_ct_len(alg, expected):
    short = b"x" * (expected // 2)
    sk = b"x" * (1632 if alg == "ml-kem-512" else 2400 if alg == "ml-kem-768" else 3168)
    with pytest.raises(ValueError, match=f"Invalid ct length: expected {expected}, got {len(short)}"):
        decapsulate(sk, short, alg)


# ========================= Edge case 11: Oversized inputs (DoS) =========================

@pytest.mark.parametrize("alg,size_field", [
    ("ml-kem-512", "pk"),
    ("ml-kem-768", "pk"),
    ("ml-kem-1024", "pk"),
])
def test_encapsulate_oversized_pk(alg, size_field):
    # 2x expected size
    if alg == "ml-kem-512":
        oversized = b"x" * 1600
    elif alg == "ml-kem-768":
        oversized = b"x" * 2368
    else:
        oversized = b"x" * 3136
    with pytest.raises(ValueError, match="Invalid pk length"):
        encapsulate(oversized, alg)


@pytest.mark.parametrize("alg", ["ml-kem-512", "ml-kem-768", "ml-kem-1024"])
def test_decapsulate_oversized_sk(alg):
    if alg == "ml-kem-512":
        oversized = b"x" * 3264
    elif alg == "ml-kem-768":
        oversized = b"x" * 4800
    else:
        oversized = b"x" * 6336
    ct = b"x" * (768 if alg == "ml-kem-512" else 1088 if alg == "ml-kem-768" else 1568)
    with pytest.raises(ValueError, match="Invalid sk length"):
        decapsulate(oversized, ct, alg)


@pytest.mark.parametrize("alg", ["ml-kem-512", "ml-kem-768", "ml-kem-1024"])
def test_decapsulate_oversized_ct(alg):
    if alg == "ml-kem-512":
        oversized = b"x" * 1536
    elif alg == "ml-kem-768":
        oversized = b"x" * 2176
    else:
        oversized = b"x" * 3136
    sk = b"x" * (1632 if alg == "ml-kem-512" else 2400 if alg == "ml-kem-768" else 3168)
    with pytest.raises(ValueError, match="Invalid ct length"):
        decapsulate(sk, oversized, alg)


# ========================= Edge case 12: Deterministic seed parameter =========================

def test_keypair_deterministic_seed_accepted():
    """deterministic=True with seed is accepted (though not actually used for reproducible keygen per R-1 probe)."""
    # Should not raise; seed is validated (32 bytes)
    pk, sk = keypair("ml-kem-768", deterministic=True, seed=bytes(32))
    assert len(pk) == 1184
    assert len(sk) == 2400


def test_keypair_deterministic_requires_seed():
    """deterministic=True with seed=None raises ValueError."""
    with pytest.raises(ValueError, match="seed must be provided when deterministic=True"):
        keypair("ml-kem-768", deterministic=True, seed=None)


def test_keypair_bad_seed_length():
    """Non-32-byte seed raises ValueError."""
    with pytest.raises(ValueError, match="seed must be 32 bytes, got 16"):
        keypair("ml-kem-768", deterministic=True, seed=bytes(16))
    with pytest.raises(ValueError, match="seed must be 32 bytes, got 64"):
        keypair("ml-kem-768", deterministic=True, seed=bytes(64))


def test_encapsulate_seed_accepted():
    """seed parameter accepted for encapsulate (API symmetry)."""
    pk, _ = keypair("ml-kem-768")
    ct, ss = encapsulate(pk, "ml-kem-768", seed=bytes(32))
    assert len(ct) == 1088
    assert len(ss) == 32


def test_decapsulate_seed_accepted():
    """seed parameter accepted for decapsulate (API symmetry, no effect)."""
    pk, sk = keypair("ml-kem-768")
    ct, ss = encapsulate(pk, "ml-kem-768")
    ss2 = decapsulate(sk, ct, "ml-kem-768", seed=bytes(32))
    assert ss == ss2


# ========================= Type errors =========================

def test_encapsulate_wrong_pk_type():
    with pytest.raises(TypeError):
        encapsulate("not bytes", "ml-kem-768")
    with pytest.raises(TypeError):
        encapsulate(None, "ml-kem-768")


def test_decapsulate_wrong_sk_type():
    ct = b"x" * 1088
    with pytest.raises(TypeError):
        decapsulate("not bytes", ct, "ml-kem-768")
    with pytest.raises(TypeError):
        decapsulate(None, ct, "ml-kem-768")


def test_decapsulate_wrong_ct_type():
    sk = b"x" * 2400
    with pytest.raises(TypeError):
        decapsulate(sk, "not bytes", "ml-kem-768")
    with pytest.raises(TypeError):
        decapsulate(sk, None, "ml-kem-768")


# The tests for sign/verify seed acceptance belong in test_sign_verify_facade.py (S3 feature)
# when that module is implemented. S2 covers KEM operations only.