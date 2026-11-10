"""Tests for matrix_status (S7).

Edge case 22: matrix_status() before corpus → returns dict with interoperability: null.
Also tests the basic shape and the with-corpus path.
"""
import os
import json
import hashlib
import tempfile
import pytest

import pqblocks_qse_sdk
from pqblocks_qse_sdk.matrix import matrix_status


class TestMatrixStatusShape:
    """Basic return-shape contract from spec §1.2."""

    def test_returns_dict(self):
        result = matrix_status()
        assert isinstance(result, dict)

    def test_has_required_top_level_keys(self):
        result = matrix_status()
        assert "implementations" in result
        assert "latest_corpus_sha256" in result
        assert "interoperability" in result

    def test_implementations_has_three_languages(self):
        result = matrix_status()
        impls = result["implementations"]
        assert "python" in impls
        assert "java" in impls
        assert "dotnet" in impls

    def test_latest_corpus_sha256_is_str_or_none(self):
        result = matrix_status()
        sha = result["latest_corpus_sha256"]
        assert sha is None or isinstance(sha, str)


class TestMatrixStatusEmpty:
    """Edge case 22: no corpus present → interoperability is null."""

    def test_matrix_empty_interoperability_null(self):
        """matrix_status() before any corpus → interoperability: null."""
        result = matrix_status()
        # When no corpus has been generated, interoperability must be null
        assert result["interoperability"] is None

    def test_matrix_empty_sha256_none(self):
        """No corpus → latest_corpus_sha256 should be None."""
        result = matrix_status()
        assert result["latest_corpus_sha256"] is None


class TestMatrixStatusWithCorpus:
    """When a corpus directory exists, matrix_status reports real values."""

    def _make_corpus_dir(self, tmpdir):
        """Create a minimal corpus layout matching §1.3."""
        alg_dir = os.path.join(tmpdir, "ml-kem-768")
        os.makedirs(alg_dir, exist_ok=True)
        with open(os.path.join(alg_dir, "seed.bin"), "wb") as f:
            f.write(b"\x00" * 32)
        with open(os.path.join(alg_dir, "pk.bin"), "wb") as f:
            f.write(b"\x01" * 1184)
        with open(os.path.join(alg_dir, "ct.bin"), "wb") as f:
            f.write(b"\x02" * 1088)
        with open(os.path.join(alg_dir, "ss.bin"), "wb") as f:
            f.write(b"\x03" * 32)
        return alg_dir

    def test_with_corpus_returns_sha256(self, tmpdir, monkeypatch):
        """With a corpus present, latest_corpus_sha256 is a 64-char hex string."""
        corpus_dir = os.path.join(tmpdir, "corpus")
        self._make_corpus_dir(corpus_dir)
        monkeypatch.setenv("QSE_CORPUS_DIR", corpus_dir)
        result = matrix_status()
        sha = result["latest_corpus_sha256"]
        assert isinstance(sha, str)
        assert len(sha) == 64
        # Verify it's valid hex
        int(sha, 16)

    def test_with_corpus_interoperability_not_null(self, tmpdir, monkeypatch):
        """With a corpus, interoperability is a dict with byte_identical and max_bit_diff."""
        corpus_dir = os.path.join(tmpdir, "corpus")
        self._make_corpus_dir(corpus_dir)
        monkeypatch.setenv("QSE_CORPUS_DIR", corpus_dir)
        result = matrix_status()
        interop = result["interoperability"]
        assert interop is not None
        assert "byte_identical" in interop
        assert "max_bit_diff" in interop
        assert isinstance(interop["byte_identical"], bool)
        assert isinstance(interop["max_bit_diff"], int)

    def test_with_corpus_byte_identical_true_for_single_impl(self, tmpdir, monkeypatch):
        """Single-implementation corpus → byte_identical True, max_bit_diff 0."""
        corpus_dir = os.path.join(tmpdir, "corpus")
        self._make_corpus_dir(corpus_dir)
        monkeypatch.setenv("QSE_CORPUS_DIR", corpus_dir)
        result = matrix_status()
        interop = result["interoperability"]
        assert interop["byte_identical"] is True
        assert interop["max_bit_diff"] == 0


class TestMatrixStatusExported:
    """matrix_status is exported from the top-level package."""

    def test_matrix_status_in_qse_namespace(self):
        assert hasattr(pqblocks_qse_sdk, "matrix_status")
        assert callable(pqblocks_qse_sdk.matrix_status)

    def test_qse_matrix_status_callable(self):
        result = pqblocks_qse_sdk.matrix_status()
        assert isinstance(result, dict)
