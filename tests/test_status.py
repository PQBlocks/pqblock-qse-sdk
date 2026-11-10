"""Tests for status (S9).

Edge case 23: status() always returns dict with version, fips_tables_version, primitive_libs.
"""
import pytest


class TestStatusShape:
    """Basic return-shape contract from spec §1.2."""

    def test_status_returns_dict(self):
        """status() must return a dict object."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        assert isinstance(result, dict)

    def test_status_has_required_top_level_keys(self):
        """status() must have version, fips_tables_version, primitive_libs keys."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        assert "version" in result, "Missing required key 'version'"
        assert "fips_tables_version" in result, "Missing required key 'fips_tables_version'"
        assert "primitive_libs" in result, "Missing required key 'primitive_libs'"

    def test_status_version_is_string(self):
        """status()['version'] must be a non-empty string."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        version = result["version"]
        assert isinstance(version, str), f"version must be str, got {type(version).__name__}"
        assert len(version) > 0, "version must be non-empty string"

    def test_status_fips_tables_version_is_string(self):
        """status()['fips_tables_version'] must be a non-empty string."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        fips_ver = result["fips_tables_version"]
        assert isinstance(fips_ver, str), f"fips_tables_version must be str, got {type(fips_ver).__name__}"
        assert len(fips_ver) > 0, "fips_tables_version must be non-empty string"

    def test_status_primitive_libs_is_dict(self):
        """status()['primitive_libs'] must be a dict with library entries."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        libs = result["primitive_libs"]
        assert isinstance(libs, dict), f"primitive_libs must be dict, got {type(libs).__name__}"
        # Must have at least pqcrypto and cryptography per spec
        assert "pqcrypto" in libs, "Missing pqcrypto in primitive_libs"
        assert "cryptography" in libs, "Missing cryptography in primitive_libs"


class TestStatusConsistency:
    """Verify status() returns consistent values across calls."""

    def test_status_is_stable(self):
        """Multiple calls to status() return the same dict structure."""
        import pqblocks_qse_sdk

        result1 = pqblocks_qse_sdk.status()
        result2 = pqblocks_qse_sdk.status()

        # Keys should be identical
        assert set(result1.keys()) == set(result2.keys())
        # Values should be stable
        assert result1["version"] == result2["version"]
        assert result1["fips_tables_version"] == result2["fips_tables_version"]


class TestStatusExported:
    """status is exported from the top-level package."""

    def test_status_in_qse_namespace(self):
        """status must be accessible as pqblocks_qse_sdk.status."""
        import pqblocks_qse_sdk

        assert hasattr(pqblocks_qse_sdk, "status"), "pqblocks_qse_sdk.status not found"
        assert callable(pqblocks_qse_sdk.status), "pqblocks_qse_sdk.status is not callable"

    def test_qse_status_callable(self):
        """pqblocks_qse_sdk.status() returns a valid response dict."""
        import pqblocks_qse_sdk

        result = pqblocks_qse_sdk.status()
        assert isinstance(result, dict)
        assert "version" in result
        assert "fips_tables_version" in result
        assert "primitive_libs" in result