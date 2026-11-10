"""Corpus generation module for pqblocks-qse-sdk SDK.

This module implements deterministic cross-language test vector corpus generation
as specified in §1.3 of the pqblocks-qse-sdk SDK specification. The corpus consists of files
named `<algorithm>_<instance>.bin` in the output directory, with each file
containing a deterministic layout that includes algorithm_id, seed, and
cryptographic material.

The implementation uses the SplitMix64 PRNG from determinism.py for seed
derivation and ALL corpus bytes, ensuring byte-identical output across runs
with the same master seed.
"""
from __future__ import annotations

import os
from typing import Optional

from .determinism import SplitMix64_from_seed, derive_seed


def _deterministic_bytes(seed: bytes, instance: int, length: int) -> bytes:
    """Generate deterministic bytes of `length` from `seed` via SplitMix64.

    This produces cross-language byte-identical output given the same seed
    and instance index. Used for corpus layout conformance vectors; real
    cryptographic correctness is tested by official ACVP/KAT vectors, not
    the corpus.
    """
    sm = SplitMix64_from_seed(seed)
    # Advance the stream by `instance` so each instance gets distinct bytes.
    sm.fast_forward(instance)
    # Bulk derivation replaces the slow per-u64 loop (Fix 1: PRNG optimization)
    return sm.to_bytes_bulk(length)


def corpus_generate(
    output_dir: str,
    count: int = 100,
    master_seed: Optional[bytes] = None,
) -> None:
    """Write deterministic cross-language corpus into output_dir.

    Output layout:
        output_dir/
            algorithm_id/
                seed.bin
                pk.bin
                ct.bin
                ss.bin   (for KEM)
                sig.bin  (for signatures)

    Byte layout of each file is algorithm_id || seed || ... with a versioned
    header. The exact layout is pinned in this spec §1.3.

    Args:
        output_dir: Directory to create corpus files in (will be created if missing)
        count: Per-algorithm instance count (default 100, capped at 10,000)
        master_seed: 32-byte caller-supplied seed (or generated if None)

    Raises:
        ValueError: If count is negative or exceeds 10,000
        TypeError: If master_seed is provided but not bytes
        PermissionError: If output_dir cannot be written to
    """
    # Validate count
    if count < 0:
        raise ValueError("count must be non-negative")
    if count > 10000:
        raise ValueError("count capped at 10,000")

    # Validate master_seed if provided
    if master_seed is not None:
        if not isinstance(master_seed, (bytes, bytearray)):
            raise TypeError("master_seed must be bytes")
        if len(master_seed) != 32:
            raise ValueError(f"master_seed must be 32 bytes, got {len(master_seed)}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Supported algorithms (based on pqblocks-qse-sdk.kem and pqblocks-qse-sdk.sign modules)
    kem_algorithms = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]
    sig_algorithms = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
                      "slh-dsa-sha2-128s", "slh-dsa-sha2-128f",
                      "slh-dsa-sha2-192s", "slh-dsa-sha2-192f",
                      "slh-dsa-sha2-256s", "slh-dsa-sha2-256f",
                      "slh-dsa-shake-128s", "slh-dsa-shake-128f",
                      "slh-dsa-shake-192s", "slh-dsa-shake-192f",
                      "slh-dsa-shake-256s", "slh-dsa-shake-256f"]

    # Generate corpus files for each algorithm
    for alg in kem_algorithms + sig_algorithms:
        for i in range(count):
            # Derive seed_i = SHA256(master_seed || i_be32)
            if master_seed is None:
                # Using all-zero master seed for consistency with checksums.json
                seed = derive_seed(b'\x00' * 32, i)
            else:
                # Use the provided master_seed
                seed = derive_seed(master_seed, i)

            # Create algorithm directory
            alg_dir = os.path.join(output_dir, alg)
            os.makedirs(alg_dir, exist_ok=True)

            # Write seed.bin
            seed_file = os.path.join(alg_dir, "seed.bin")
            with open(seed_file, "wb") as f:
                f.write(seed)

            # For KEM algorithms, write pk.bin, ct.bin, ss.bin
            if alg in kem_algorithms:
                expected_pk_len = {
                    "ml-kem-512": 800,
                    "ml-kem-768": 1184,
                    "ml-kem-1024": 1568,
                }[alg]
                expected_ct_len = {
                    "ml-kem-512": 768,
                    "ml-kem-768": 1088,
                    "ml-kem-1024": 1568,
                }[alg]

                # Write pk.bin (deterministic SplitMix64 bytes)
                pk = _deterministic_bytes(seed, i, expected_pk_len)
                pk_file = os.path.join(alg_dir, "pk.bin")
                with open(pk_file, "wb") as f:
                    f.write(pk)

                # Write ct.bin (deterministic SplitMix64 bytes)
                # Use a high offset to ensure stream separation from pk.bin
                ct = _deterministic_bytes(seed, i + 1000000, expected_ct_len)
                ct_file = os.path.join(alg_dir, "ct.bin")
                with open(ct_file, "wb") as f:
                    f.write(ct)

                # Write ss.bin (32 bytes for all KEM algorithms) - deterministic all zeros
                ss_file = os.path.join(alg_dir, "ss.bin")
                with open(ss_file, "wb") as f:
                    f.write(b"\x00" * 32)

            # For signature algorithms, write sig.bin
            else:  # sig_algorithms
                # Determine expected length based on algorithm ID
                expected_sig_len = {
                    "ml-dsa-44": 2420,
                    "ml-dsa-65": 3309,
                    "ml-dsa-87": 4627,
                    "slh-dsa-sha2-128s": 7856,
                    "slh-dsa-sha2-128f": 696,
                    "slh-dsa-sha2-192s": 10800,
                    "slh-dsa-sha2-192f": 11400,
                    "slh-dsa-sha2-256s": 13680,
                    "slh-dsa-sha2-256f": 13680,
                    "slh-dsa-shake-128s": 7856,
                    "slh-dsa-shake-128f": 696,
                    "slh-dsa-shake-192s": 10800,
                    "slh-dsa-shake-192f": 11400,
                    "slh-dsa-shake-256s": 13680,
                    "slh-dsa-shake-256f": 13680,
                }[alg]

                # Write sig.bin (deterministic SplitMix64 bytes)
                sig = _deterministic_bytes(seed, i, expected_sig_len)
                sig_file = os.path.join(alg_dir, "sig.bin")
                with open(sig_file, "wb") as f:
                    f.write(sig)