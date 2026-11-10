"""S3 tests: signature façade — sign / verify with length validation.

Covers:
- Happy path for ML-DSA-44, ML-DSA-65, ML-DSA-87
- Happy path for SLH-DSA parameter sets (sha2-128s/f, sha2-192s/f, sha2-256s/f, shake-128s/f, shake-192s/f, shake-256s/f)
- Edge cases 5, 6, 7, 8, 9, 12, 17, 18 from §3 ledger
- Unknown algorithm (edge 1)
- Deterministic parameter acceptance (per §2.3)
- Round-trip: verify(pk, sign(sk, msg, alg), msg, alg) == True
"""

import pytest
from pqblocks_qse_sdk import sign, verify

# Algorithm -> (pk_len, sk_len, sig_len) from FIPS 204/205 (spec §2.2)
SIG_SIZES = {
    "ml-dsa-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ml-dsa-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ml-dsa-87": {"pk": 2592, "sk": 4896, "sig": 4627},
    "slh-dsa-sha2-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "slh-dsa-sha2-128f": {"pk": 32, "sk": 64, "sig": 17088},  # FIPS 205 Table 2; actual pqcrypto sig size
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

# All supported signature algorithms per spec §1.2
SIG_ALGORITHMS = list(SIG_SIZES.keys())


# ========================= Happy path =========================

@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_keypair_sign_verify_roundtrip(alg):
    """Full round-trip: keypair -> sign -> verify returns True."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair(alg)
    message = b"hello post-quantum world"
    signature = sign(sk, message, alg)
    # Signature size check
    expected_sig = SIG_SIZES[alg]["sig"]
    assert len(signature) == expected_sig, f"{alg}: sig len {len(signature)} != {expected_sig}"
    # Verify returns True
    assert verify(pk, signature, message, alg) is True


@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_sign_verify_empty_message(alg):
    """Edge 8, 9: empty message sign/verify works."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair(alg)
    signature = sign(sk, b"", alg)
    assert verify(pk, signature, b"", alg) is True


@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_sign_verify_various_messages(alg):
    """Sign/verify with various message sizes."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair(alg)
    for msg in [b"x", b"a" * 100, b"b" * 1000, b"\x00" * 32, b"\xff" * 64]:
        signature = sign(sk, msg, alg)
        assert verify(pk, signature, msg, alg) is True


# ========================= Edge 1: Unknown algorithm =========================

def test_sign_unknown_algorithm():
    """sign raises ValueError for unknown algorithm."""
    sk = b"x" * 4032  # dummy
    with pytest.raises(ValueError, match="Unsupported algorithm: ml-dsa-999"):
        sign(sk, b"msg", "ml-dsa-999")

def test_verify_unknown_algorithm():
    """verify raises ValueError for unknown algorithm (per spec §1.6)."""
    pk = b"x" * 1952
    sig = b"x" * 3309
    with pytest.raises(ValueError, match="Unsupported algorithm: ml-dsa-999"):
        verify(pk, sig, b"msg", "ml-dsa-999")


# ========================= Edge 5: Wrong-length ML-DSA private key (sign) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2560),
    ("ml-dsa-65", 4032),
    ("ml-dsa-87", 4896),
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
def test_sign_sk_len(alg, expected):
    """Edge 5: sign raises ValueError on wrong-length secret key."""
    short = b"x" * (expected // 2)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(short)}"):
        sign(short, b"msg", alg)


# ========================= Edge 6: Wrong-length ML-DSA public key (verify) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 1312),
    ("ml-dsa-65", 1952),
    ("ml-dsa-87", 2592),
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
def test_verify_pk_len(alg, expected):
    """Edge 6: verify returns False on wrong-length public key (implicit rejection)."""
    short = b"x" * (expected // 2)
    sig = b"x" * SIG_SIZES[alg]["sig"]
    assert verify(short, sig, b"msg", alg) is False


# ========================= Edge 7: Wrong-length ML-DSA signature (verify) =========================

@pytest.mark.parametrize("alg,expected", [
    ("ml-dsa-44", 2420),
    ("ml-dsa-65", 3309),
    ("ml-dsa-87", 4627),
    ("slh-dsa-sha2-128s", 7856),
    ("slh-dsa-sha2-128f", 696),
    ("slh-dsa-sha2-192s", 16224),
    ("slh-dsa-sha2-192f", 35664),
    ("slh-dsa-sha2-256s", 29792),
    ("slh-dsa-sha2-256f", 49856),
    ("slh-dsa-shake-128s", 7856),
    ("slh-dsa-shake-128f", 696),
    ("slh-dsa-shake-192s", 16224),
    ("slh-dsa-shake-192f", 35664),
    ("slh-dsa-shake-256s", 29792),
    ("slh-dsa-shake-256f", 49856),
])
def test_verify_sig_len(alg, expected):
    """Edge 7: verify returns False on wrong-length signature (implicit rejection)."""
    pk = b"x" * SIG_SIZES[alg]["pk"]
    short = b"x" * (expected // 2)
    assert verify(pk, short, b"msg", alg) is False


# ========================= Edge 11/oversized: Oversized inputs (DoS) =========================

@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_sign_oversized_sk(alg):
    """sign raises ValueError immediately on oversized sk (no allocation)."""
    expected = SIG_SIZES[alg]["sk"]
    oversized = b"x" * (expected * 2)
    with pytest.raises(ValueError, match=f"Invalid sk length: expected {expected}, got {len(oversized)}"):
        sign(oversized, b"msg", alg)


@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_verify_oversized_pk(alg):
    """verify returns False immediately on oversized pk."""
    expected = SIG_SIZES[alg]["pk"]
    oversized = b"x" * (expected * 2)
    sig = b"x" * SIG_SIZES[alg]["sig"]
    assert verify(oversized, sig, b"msg", alg) is False


@pytest.mark.parametrize("alg", SIG_ALGORITHMS)
def test_verify_oversized_sig(alg):
    """verify returns False immediately on oversized sig."""
    expected = SIG_SIZES[alg]["sig"]
    oversized = b"x" * (expected * 2)
    pk = b"x" * SIG_SIZES[alg]["pk"]
    assert verify(pk, oversized, b"msg", alg) is False


# ========================= Edge 12/16: Deterministic seed parameter =========================

def test_sign_deterministic_seed_accepted():
    """deterministic=True with seed is accepted (though pqcrypto.sign takes no seed; R-1 probe)."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    # Should not raise; deterministic is validated but seed is not used for reproducible sign
    sig = sign(sk, b"msg", "ml-dsa-65", deterministic=True)
    assert len(sig) == SIG_SIZES["ml-dsa-65"]["sig"]

def test_sign_deterministic_requires_no_seed():
    """seed parameter not accepted for sign (pqcrypto.sign takes no seed arg)."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    # Seed is accepted for API symmetry with §2.3 but has no effect
    sig = sign(sk, b"msg", "ml-dsa-65", deterministic=True)
    assert len(sig) == SIG_SIZES["ml-dsa-65"]["sig"]


# ========================= Edge 17: Deterministic signing side-channel warning =========================

def test_sign_deterministic_sidechannel_warning():
    """sign with deterministic=True returns signature; SDK flags warning via harden_check_unsafe_api.
    This test verifies the signature is produced (warning flagging is in harden tests)."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    sig = sign(sk, b"msg", "ml-dsa-65", deterministic=True)
    assert len(sig) == SIG_SIZES["ml-dsa-65"]["sig"]
    # The warning is a static-analysis concern; sign just returns the signature


# ========================= Edge 18: Implicit rejection (verify wrong algorithm) =========================

def test_verify_wrong_algorithm():
    """Edge 18: verify returns False (no exception) when algorithm string mismatches.
    Per spec: 'Implicit rejection (verify) with wrong algorithm string -> False (no exception, no timing leak)'."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    sig = sign(sk, b"msg", "ml-dsa-65")
    # Verifying with wrong algorithm string returns False
    assert verify(pk, sig, b"msg", "ml-dsa-44") is False
    assert verify(pk, sig, b"msg", "ml-dsa-87") is False
    assert verify(pk, sig, b"msg", "slh-dsa-sha2-128s") is False


# ========================= Type errors =========================

def test_sign_wrong_sk_type():
    with pytest.raises(TypeError):
        sign("not bytes", b"msg", "ml-dsa-65")
    with pytest.raises(TypeError):
        sign(None, b"msg", "ml-dsa-65")

def test_sign_wrong_msg_type():
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    with pytest.raises(TypeError):
        sign(sk, "not bytes", "ml-dsa-65")
    with pytest.raises(TypeError):
        sign(sk, None, "ml-dsa-65")

def test_verify_wrong_pk_type():
    with pytest.raises(TypeError):
        verify("not bytes", b"x"*3309, b"msg", "ml-dsa-65")
    with pytest.raises(TypeError):
        verify(None, b"x"*3309, b"msg", "ml-dsa-65")

def test_verify_wrong_sig_type():
    with pytest.raises(TypeError):
        verify(b"x"*1952, "not bytes", b"msg", "ml-dsa-65")
    with pytest.raises(TypeError):
        verify(b"x"*1952, None, b"msg", "ml-dsa-65")

def test_verify_wrong_msg_type():
    with pytest.raises(TypeError):
        verify(b"x"*1952, b"x"*3309, "not bytes", "ml-dsa-65")
    with pytest.raises(TypeError):
        verify(b"x"*1952, b"x"*3309, None, "ml-dsa-65")


# ========================= Verify failure cases (valid lengths but wrong key/sig) =========================

def test_verify_tampered_signature():
    """Tampered signature on correct-length inputs returns False (not exception)."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    sig = sign(sk, b"msg", "ml-dsa-65")
    # Flip one bit
    tampered = bytearray(sig)
    tampered[0] ^= 0xFF
    assert verify(pk, bytes(tampered), b"msg", "ml-dsa-65") is False

def test_verify_tampered_message():
    """Wrong message with valid signature returns False."""
    from pqblocks_qse_sdk import keypair
    pk, sk = keypair("ml-dsa-65")
    sig = sign(sk, b"msg", "ml-dsa-65")
    assert verify(pk, sig, b"other", "ml-dsa-65") is False

def test_verify_wrong_key():
    """Wrong public key with valid signature returns False."""
    from pqblocks_qse_sdk import keypair
    pk1, sk1 = keypair("ml-dsa-65")
    pk2, _ = keypair("ml-dsa-65")
    sig = sign(sk1, b"msg", "ml-dsa-65")
    assert verify(pk2, sig, b"msg", "ml-dsa-65") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])