"""S5 tests: SplitMix64 wrapper and seed derivation.

Covers spec §2.3–2.4:
- Edge case 12: Deterministic seed reuse → same seed → identical keypair
- Edge case 15: Cross-language seed derivation → same master_seed + i → same seed_i
- Edge case 28: SplitMix64 fan-out collision → different i produce same seed (impossible)

From spec:
- seed_i = SHA256(master_seed || i_be32) for corpus generation
- SplitMix64 is used as the deterministic CSPRNG for the seed derivation
- All seeds are 32 bytes
"""

import hashlib
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))

from pqblocks_qse_sdk.determinism import derive_seed, SplitMix64


# -----------------------------------------------------------------------------
# Edge case 12: Deterministic seed reuse
# Same master_seed + same i → same 32-byte seed output (bit-identical)
# -----------------------------------------------------------------------------

def test_derive_seed_same_input_same_output():
    """Same master_seed and i must produce identical 32-byte seeds."""
    master_seed = b"\x00" * 32
    i = 0
    seed1 = derive_seed(master_seed, i)
    seed2 = derive_seed(master_seed, i)
    assert seed1 == seed2, "Same inputs should produce identical seeds"
    assert len(seed1) == 32, "Derived seed must be 32 bytes"


# -----------------------------------------------------------------------------
# Edge case 15: Cross-language seed derivation
# seed_i == SHA256(master_seed || i_be32)
# -----------------------------------------------------------------------------

def test_derive_seed_matches_sha256_formula():
    """Each seed_i must equal SHA256(master_seed || i_be32)."""
    master_seed = b"\xde\xad\xbe\xef" + b"\x00" * 28
    for i in [0, 1, 42, 1000, 999999]:
        expected = hashlib.sha256(master_seed + struct.pack(">I", i)).digest()
        actual = derive_seed(master_seed, i)
        assert actual == expected, f"derive_seed(master_seed, {i}) != SHA256(master_seed || i)"


# -----------------------------------------------------------------------------
# Edge case 28: SplitMix64 fan-out collision
# Different i produce different seeds (practically impossible for collision)
# -----------------------------------------------------------------------------

def test_seed_no_collision_across_65536_instances():
    """
    Test that 2^16 different indices produce distinct seeds.
    Collision is practically impossible but we verify the fan-out works.
    """
    master_seed = b"\x01\x02\x03\x04" + b"\x00" * 28
    seen = set()
    for i in range(65536):
        seed = derive_seed(master_seed, i)
        assert seed not in seen, f"Collision detected at i={i}"
        seen.add(seed)
    assert len(seen) == 65536, "All 65536 seeds should be unique"


# -----------------------------------------------------------------------------
# Negative tests: error handling for derive_seed
# -----------------------------------------------------------------------------

def test_derive_seed_wrong_master_seed_length():
    """Non-32-byte master_seed raises ValueError."""
    short_seed = b"\x00" * 16
    with pytest.raises(ValueError, match="master_seed must be 32 bytes"):
        derive_seed(short_seed, 0)


def test_derive_seed_wrong_master_seed_type():
    """Non-bytes master_seed raises TypeError."""
    with pytest.raises(TypeError, match="master_seed must be bytes"):
        derive_seed("not bytes", 0)


def test_derive_seed_wrong_i_type():
    """Non-integer i raises TypeError."""
    master_seed = b"\x00" * 32
    with pytest.raises(TypeError, match="i must be an integer"):
        derive_seed(master_seed, "not an int")


def test_derive_seed_negative_i():
    """Negative i raises ValueError."""
    master_seed = b"\x00" * 32
    with pytest.raises(ValueError, match="i must be a non-negative integer"):
        derive_seed(master_seed, -1)


# -----------------------------------------------------------------------------
# SplitMix64 class tests (reference implementation verification)
# -----------------------------------------------------------------------------

def test_splitmix64_next_u64_deterministic():
    """SplitMix64.next_u64() must be deterministic (same state → same output).

    Values verified against the canonical SplitMix64 reference
    (Steele et al., Splittable Pseudorandom Number Generators).
    """
    sm = SplitMix64(0x123456789ABCDEF0)
    assert sm.next_u64() == 0x161922C645CE50E8, "SplitMix64 round 0 mismatch"
    assert sm.next_u64() == 0xAD760CAFA1697B60, "SplitMix64 round 1 mismatch"
    assert sm.next_u64() == 0x3501FF44902CA50D, "SplitMix64 round 2 mismatch"


def test_splitmix64_canonical_seed_zero_vector():
    """Canonical published KAT: SplitMix64(0) first output is 0xe220a8397b1dcdaf.

    Guards the 64-bit wrap semantics (mask after each multiply) that a
    naive Python port silently gets wrong.
    """
    sm = SplitMix64(0)
    assert sm.next_u64() == 0xE220A8397B1DCDAF


def test_splitmix64_state_advances():
    """Each call to next_u64() advances state."""
    sm1 = SplitMix64(0xDEADBEEF)
    sm2 = SplitMix64(0xDEADBEEF)
    assert sm1.next_u64() == sm2.next_u64(), "Same seed → same first output"
    assert sm1.next_u64() == sm2.next_u64(), "State advanced consistently"


def test_splitmix64_to_bytes_32():
    """SplitMix64.to_bytes(32) produces 32 bytes from 4 calls to next_u64."""
    sm = SplitMix64(0)
    b = sm.to_bytes(32)
    assert len(b) == 32, "to_bytes(32) must produce 32 bytes"


# -----------------------------------------------------------------------------
# Edge case ledger tests (S5 specific negative tests)
# -----------------------------------------------------------------------------

def test_derive_seed_various_indices():
    """Verify derive_seed works correctly across various indices."""
    master_seed = hashlib.sha256(b"test master").digest()
    for i in [0, 1, 12, 15, 28]:
        seed = derive_seed(master_seed, i)
        assert len(seed) == 32, f"Derived seed for i={i} must be 32 bytes"
        # Verify it matches the expected SHA256 formula
        expected = hashlib.sha256(master_seed + struct.pack(">I", i)).digest()
        assert seed == expected, f"derive_seed(master_seed, {i}) mismatch"


# Unit tests for internal validation helpers (via public builder functions)

def test_validate_master_seed_wrong_type():
    """_validate_master_seed raises TypeError on non-bytes."""
    from pqblocks_qse_sdk.determinism import _validate_master_seed
    with pytest.raises(TypeError, match="master_seed must be bytes"):
        _validate_master_seed("not bytes")


def test_validate_master_seed_wrong_length():
    """_validate_master_seed raises ValueError on wrong length."""
    from pqblocks_qse_sdk.determinism import _validate_master_seed
    with pytest.raises(ValueError, match="master_seed must be 32 bytes"):
        _validate_master_seed(b"\x00" * 16)


def test_validate_i_wrong_type():
    """_validate_i raises TypeError on non-integer."""
    from pqblocks_qse_sdk.determinism import _validate_i
    with pytest.raises(TypeError, match="i must be an integer"):
        _validate_i("not an int")


def test_validate_i_negative():
    """_validate_i raises ValueError on negative."""
    from pqblocks_qse_sdk.determinism import _validate_i
    with pytest.raises(ValueError, match="i must be a non-negative integer"):
        _validate_i(-1)


def test_validate_seed_wrong_type():
    """_validate_seed raises TypeError on non-bytes."""
    from pqblocks_qse_sdk.determinism import _validate_seed
    with pytest.raises(TypeError, match="seed must be bytes"):
        _validate_seed("not bytes")


def test_validate_seed_wrong_length():
    """_validate_seed raises ValueError on wrong length."""
    from pqblocks_qse_sdk.determinism import _validate_seed
    with pytest.raises(ValueError, match="seed must be 32 bytes"):
        _validate_seed(b"\x00" * 16)


# Unit tests for builder functions

def test_splitmix64_from_seed():
    """SplitMix64_from_seed creates a PRNG from a 32-byte seed."""
    from pqblocks_qse_sdk.determinism import SplitMix64_from_seed
    seed = b"\x00" * 32
    sm = SplitMix64_from_seed(seed)
    assert isinstance(sm, SplitMix64)
    assert sm.next_u64() == 0xE220A8397B1DCDAF, "Canonical SplitMix64(0) first output"


def test_splitmix64_from_i():
    """SplitMix64_from_i creates a PRNG from master_seed + i (spec §2.4).

    seed_i = SHA256(master_seed || i_be32); the PRNG state is the first 8
    bytes of seed_i (big-endian). This is NOT the same as SplitMix64(0)
    unless SHA256(00*32 || 0_be32) happens to be all-zero bytes, which it
    is not — so the expected constant below is the independent derivation,
    not the SplitMix64(0) canonical output.
    """
    from pqblocks_qse_sdk.determinism import SplitMix64_from_i
    master_seed = b"\x00" * 32
    sm = SplitMix64_from_i(master_seed, 0)
    assert isinstance(sm, SplitMix64)
    # Independent derivation: SHA256(00*32 || 0x00000000)[:8] interpreted as u64 BE
    # then one SplitMix64 step. Value verified against an independent reference
    # implementation (not importing the product).
    assert sm.next_u64() == 0xDD1BA57E8DCD734C, (
        f"Expected 0xDD1BA57E8DCD734C from independent derivation, "
        f"got 0x{sm.next_u64():016X}")


# Edge cases for to_bytes

def test_splitmix64_to_bytes_zero():
    """SplitMix64.to_bytes(0) returns empty bytes."""
    sm = SplitMix64(0)
    b = sm.to_bytes(0)
    assert b == b""


def test_splitmix64_to_bytes_one():
    """SplitMix64.to_bytes(1) returns 1 byte."""
    sm = SplitMix64(0)
    b = sm.to_bytes(1)
    assert len(b) == 1
    assert b[0] == 0xAF  # LSB of first output 0xE220A8397B1DCDAF


def test_splitmix64_to_bytes_33_error():
    """SplitMix64.to_bytes(33) raises ValueError."""
    sm = SplitMix64(0)
    with pytest.raises(ValueError, match="length must be <= 32"):
        sm.to_bytes(33)


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
    pytest.main([__file__, "-v"])