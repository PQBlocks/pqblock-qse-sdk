import os
import tempfile
import pytest

from pqblocks_qse_sdk.corpus import corpus_generate


def test_corpus_permission_error():
    """Edge case 13: Corpus output directory permissions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a directory that cannot be written to
        unwritable_dir = os.path.join(tmpdir, "unwritable")
        os.makedirs(unwritable_dir, exist_ok=True)
        os.chmod(unwritable_dir, 0o000)
        try:
            with pytest.raises(PermissionError):
                corpus_generate(unwritable_dir, count=1)
        finally:
            os.chmod(unwritable_dir, 0o755)


def test_corpus_idempotent():
    """Edge case 14: Corpus output existing files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        # First run
        corpus_generate(corpus_dir, count=2)
        # Check files exist inside algorithm subdirectories
        files = []
        for root, _, filenames in os.walk(corpus_dir):
            for fn in filenames:
                if fn.endswith(".bin"):
                    files.append(os.path.join(root, fn))
        assert len(files) >= 3  # at least 3 algorithms × some files each

        # Second run - should not crash and files should be updated or handled appropriately
        corpus_generate(corpus_dir, count=1)
        files_after = []
        for root, _, filenames in os.walk(corpus_dir):
            for fn in filenames:
                if fn.endswith(".bin"):
                    files_after.append(os.path.join(root, fn))
        assert len(files_after) >= 3


def test_corpus_negative_count():
    """Edge case 24: Negative count in corpus_generate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        with pytest.raises(ValueError, match="count must be non-negative"):
            corpus_generate(corpus_dir, count=-5)


def test_corpus_count_cap():
    """Edge case 25: Excessive count in corpus_generate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        with pytest.raises(ValueError, match="capped at 10,000"):
            corpus_generate(corpus_dir, count=1_000_000)


def test_corpus_corrupt_seed():
    """Edge case 27: Corrupted seed.bin in corpus."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        # Create a normal corpus first
        corpus_generate(corpus_dir, count=5)

        # Corrupt one seed.bin file
        seed_file = os.path.join(corpus_dir, "ml-kem-768", "seed.bin")
        with open(seed_file, "wb") as f:
            f.write(b"corrupted data that is not 32 bytes")

        # corpus_generate should handle this gracefully (log and skip or regenerate)
        # This test ensures it doesn't crash
        corpus_generate(corpus_dir, count=3)


def test_master_seed_type_error():
    """Edge case for master_seed TypeError (corpus.py line 59)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        with pytest.raises(TypeError, match="master_seed must be bytes"):
            corpus_generate(corpus_dir, count=1, master_seed="not_bytes")


def test_master_seed_length_error():
    """Edge case for master_seed length error (corpus.py line 61)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        with pytest.raises(ValueError, match="master_seed must be 32 bytes"):
            corpus_generate(corpus_dir, count=1, master_seed=b"32byte")


def test_master_seed_valid():
    """Edge case 88: Valid master_seed derivation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        # Valid 32-byte master seed
        valid_seed = os.urandom(32)
        corpus_generate(corpus_dir, count=2, master_seed=valid_seed)
        # Verify files were created
        files = []
        for root, _, filenames in os.walk(corpus_dir):
            for fn in filenames:
                if fn.endswith(".bin"):
                    files.append(os.path.join(root, fn))
        assert len(files) >= 3  # at least 3 algorithms × some files each


def test_corpus_zero_count():
    """Edge case: Zero count."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = os.path.join(tmpdir, "corpus")
        corpus_generate(corpus_dir, count=0)
        # Should not create any files
        files = []
        for root, _, filenames in os.walk(corpus_dir):
            for fn in filenames:
                if fn.endswith(".bin"):
                    files.append(os.path.join(root, fn))
        assert len(files) == 0