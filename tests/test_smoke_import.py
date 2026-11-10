"""S1 smoke test: verify pqblocks_qse_sdk SDK imports with >=8 public exports."""
import sys
import pytest

def test_smoke_import():
    """All 9 required exports must be accessible from the pqblocks_qse_sdk package."""
    import pqblocks_qse_sdk
    # The spec requires >=8 public exports:
    # keypair, encapsulate, decapsulate, sign, verify, corpus_generate,
    # matrix_status, harden_check_unsafe_api, status
    expected = {
        "keypair", "encapsulate", "decapsulate", "sign", "verify",
        "corpus_generate", "matrix_status", "harden_check_unsafe_api", "status"
    }
    actual = set(dir(pqblocks_qse_sdk))
    missing = expected - actual
    assert not missing, f"Missing exports: {sorted(missing)}"
    # Verify count >= 8
    assert len(actual & expected) >= 8, f"Expected >=8 exports, got {len(actual & expected)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])