import hashlib
import os
import tempfile
import pytest

from pqblocks_qse_sdk.corpus import corpus_generate


def _sha256_file(path: str) -> str:
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_files(corpus_dir: str) -> dict[str, str]:
    """Collect all .bin files under corpus dir, keyed by relative path."""
    result = {}
    for root, _, filenames in os.walk(corpus_dir):
        for fn in filenames:
            if fn.endswith(".bin"):
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, corpus_dir)
                result[rel] = full
    return result


def _run_corpus(output_dir: str, master_seed: bytes) -> dict[str, str]:
    """Run corpus_generate and return {relative_path: sha256_hex}."""
    corpus_generate(output_dir, count=3, master_seed=master_seed)
    files = _collect_files(output_dir)
    return {rel: _sha256_file(full) for rel, full in files.items()}


def test_corpus_determinism_same_seed() -> None:
    """S13: corpus_generate with same master_seed must produce byte-identical files.

    Per spec §4.4: corpus_generate run twice with the same master seed
    produces byte-identical files (sha256 comparison).
    """
    master_seed = os.urandom(32)
    with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
        run1 = _run_corpus(tmpdir1, master_seed)
        run2 = _run_corpus(tmpdir2, master_seed)

        all_keys = sorted(set(run1.keys()) | set(run2.keys()))
        diffs = []
        for key in all_keys:
            h1 = run1.get(key)
            h2 = run2.get(key)
            if h1 != h2:
                diffs.append((key, h1, h2))

        assert not diffs, (
            f"Corpus files differ across runs with same master seed:\n"
            + "\n".join(f"  {k}: run1={h1} run2={h2}" for k, h1, h2 in diffs)
        )