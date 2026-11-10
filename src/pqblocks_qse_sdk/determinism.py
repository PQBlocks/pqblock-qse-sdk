"""Deterministic seed derivation module for pqblocks-qse-sdk SDK.

Implements SplitMix64 PRNG and seed derivation per spec §2.3–2.4:
- seed_i = SHA256(master_seed || i_be32) for corpus generation
- SplitMix64 is used as the deterministic CSPRNG for the seed derivation
- All seeds are 32 bytes
"""

from __future__ import annotations

import hashlib
import struct


class SplitMix64:
    """SplitMix64 PRNG - 64-bit state, deterministic, fast.

    Reference: https://github.com/PrincetonUniversity/SplitMix64
    C semantics: unsigned overflow wraps modulo 2^64.
    """

    M = 0xFFFFFFFFFFFFFFFF
    GAMMA = 0x9E3779B97F4A7C15

    def __init__(self, seed: int | bytes) -> None:
        if isinstance(seed, bytes):
            if len(seed) != 32:
                raise ValueError("seed must be 32 bytes")
            # SplitMix64 state is 64 bits; derive it from the first 8 bytes
            # of the 32-byte seed (big-endian), deterministic and canonical.
            self.state = struct.unpack(">Q", seed[:8])[0]
        else:
            self.state = int(seed) & self.M

    def next_u64(self) -> int:
        """Advance state and return next 64-bit integer."""
        # C semantics: state += 0x9e3779b97f4a7c15 wraps modulo 2^64
        self.state = (self.state + self.GAMMA) & self.M
        z = self.state
        # First multiply, modulo 2^64
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.M
        # Second XOR+shift
        z = z ^ (z >> 27)
        # Second multiply, modulo 2^64
        z = (z * 0x94D049BB133111EB) & self.M
        # Final XOR+shift
        z = z ^ (z >> 31)
        return z & self.M

    def next_u32(self) -> int:
        """Advance state and return next 32-bit integer."""
        return self.next_u64() & 0xFFFFFFFF

    def to_bytes(self, length: int) -> bytes:
        """Derive `length` bytes from successive next_u64() calls."""
        if length <= 0:
            return b""
        if length > 32:
            raise ValueError("length must be <= 32")
        result = bytearray()
        while len(result) < length:
            val = self.next_u64()
            for i in range(8):
                if len(result) >= length:
                    break
                result.append((val >> (i * 8)) & 0xFF)
        return bytes(result)

    def to_bytes_bulk(self, n: int) -> bytes:
        """Derive `n` bytes in one pass (bulk, much faster than repeated to_bytes() calls).

        Same SplitMix64 algorithm, generating 64-bit words and packing via
        little-endian byte representation matching canonical reference implementations.

        Args:
            n: Number of bytes to generate (any non-negative integer).

        Returns:
            bytes object of exactly n bytes, deterministic for this PRNG state.
        """
        if n <= 0:
            return b""
        words = (n + 7) // 8
        result = bytearray()
        for _ in range(words):
            val = self.next_u64()
            result.extend(val.to_bytes(8, "little"))
        return bytes(result[:n])

    def fast_forward(self, steps: int) -> None:
        """Advance the SplitMix64 state by `steps` without generating output.

        SplitMix64's state advances by GAMMA on each call, so k calls advance
        the state additively: state_{n+k} = state_n + k * GAMMA (mod 2^64).
        This equivalent closed-form jump replaces a Python loop of k next_u64()
        calls used only to reach a later point in the same stream.

        Correctness is regression-netted against the loop it replaces:
        _deterministic_bytes() must still reproduce interop/checksums.json
        byte-for-byte (test_corpus_interop_byte_identity.py).

        Args:
            steps: Number of next_u64() calls to skip (non-negative).

        Raises:
            ValueError: If steps is negative.
        """
        if steps < 0:
            raise ValueError("steps must be non-negative")
        if steps == 0:
            return
        # state_{n+steps} = (state_n + steps * GAMMA) mod 2^64
        self.state = (self.state + steps * self.GAMMA) & self.M


def derive_seed(master_seed: bytes, i: int) -> bytes:
    """Derive 32-byte seed_i = SHA256(master_seed || i_be32).

    Per spec §2.3–2.4: seed_i == SHA256(master_seed || i_be32)
    """
    if not isinstance(master_seed, (bytes, bytearray)):
        raise TypeError("master_seed must be bytes")
    if len(master_seed) != 32:
        raise ValueError("master_seed must be 32 bytes")
    if not isinstance(i, int):
        raise TypeError("i must be an integer")
    if i < 0:
        raise ValueError("i must be a non-negative integer")

    # SHA256(master_seed || i_be32)
    i_be32 = struct.pack(">I", i)
    data = master_seed + i_be32
    return hashlib.sha256(data).digest()


def _validate_master_seed(master_seed: bytes) -> None:
    if not isinstance(master_seed, (bytes, bytearray)):
        raise TypeError("master_seed must be bytes")
    if len(master_seed) != 32:
        raise ValueError("master_seed must be 32 bytes")


def _validate_i(i: int) -> None:
    if not isinstance(i, int):
        raise TypeError("i must be an integer")
    if i < 0:
        raise ValueError("i must be a non-negative integer")


def _validate_seed(seed: bytes) -> None:
    if not isinstance(seed, bytes):
        raise TypeError("seed must be bytes")
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")


def SplitMix64_from_seed(seed: bytes) -> SplitMix64:
    """Create SplitMix64 instance from 32-byte seed."""
    _validate_seed(seed)
    return SplitMix64(seed)


def SplitMix64_from_i(master_seed: bytes, i: int) -> SplitMix64:
    """Create SplitMix64 instance from master_seed + i."""
    _validate_master_seed(master_seed)
    _validate_i(i)
    seed_i = derive_seed(master_seed, i)
    return SplitMix64_from_seed(seed_i)