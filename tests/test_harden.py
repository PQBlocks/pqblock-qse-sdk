"""Tests for harden_check_unsafe_api (S8).

Edge cases from spec §3:
- 20: harden_check_unsafe_api on module without AST → TypeError or graceful empty findings
- 21: harden_check_unsafe_api false negative → Module uses deprecated PQC path → Finding with severity="high"
- 31: harden_check_unsafe_api file-path target → AST-walks that file; findings carry the file field
- 32: harden_check_unsafe_api directory target → Recursive *.py walk beneath the directory
- 33: harden_check_unsafe_api non-existent path → ValueError naming the target string
- 34: harden_check_unsafe_api unresolvable module name → ValueError naming the target string
"""
import os
import sys
import tempfile
import pytest

# Ensure fixtures are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))

from pqblocks_qse_sdk.harden import harden_check_unsafe_api


class TestHardenCheckUnsafeAPIShape:
    """Basic return-shape contract from spec §1.2."""

    def test_returns_dict(self):
        result = harden_check_unsafe_api(sys.modules[__name__])
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = harden_check_unsafe_api(sys.modules[__name__])
        assert "findings" in result
        assert "count" in result

    def test_findings_is_list(self):
        result = harden_check_unsafe_api(sys.modules[__name__])
        assert isinstance(result["findings"], list)

    def test_count_is_int(self):
        result = harden_check_unsafe_api(sys.modules[__name__])
        assert isinstance(result["count"], int)
        assert result["count"] == len(result["findings"])

    def test_finding_structure(self):
        """Each finding has file, line, pattern, severity."""
        import tests.fixtures.unsafe_module as unsafe_mod
        result = harden_check_unsafe_api(unsafe_mod)
        for finding in result["findings"]:
            assert "file" in finding
            assert "line" in finding
            assert "pattern" in finding
            assert "severity" in finding
            assert isinstance(finding["file"], str)
            assert isinstance(finding["line"], int)
            assert isinstance(finding["pattern"], str)
            assert isinstance(finding["severity"], str)


class TestHardenEdgeCase20:
    """Edge case 20: Non-Python module object → TypeError or graceful empty findings."""

    def test_non_module_object_raises_typeerror_or_returns_empty(self):
        """Passing a non-module OBJECT (not a str target) → TypeError or graceful empty findings.

        A ``str`` is NOT an object here — it is the documented string *target*
        intake (spec §1.2), so it is deliberately excluded from this case and
        covered by edge cases 31-34.
        """
        for bad_input in (123, 4.5, {"foo": "bar"}, None, [], (), set(), True):
            result = harden_check_unsafe_api(bad_input)
            # Spec allows either TypeError or graceful empty findings
            if isinstance(result, dict):
                assert result["findings"] == []
                assert result["count"] == 0


class TestHardenEdgeCase21:
    """Edge case 21: Module uses deprecated PQC path → Finding with severity='high'."""

    def test_finds_deprecated_pqc_path(self):
        """Module with deprecated PQC API usage should return findings with severity='high'."""
        import tests.fixtures.unsafe_module as unsafe_mod
        result = harden_check_unsafe_api(unsafe_mod)
        assert result["count"] >= 1
        high_severity = [f for f in result["findings"] if f["severity"] == "high"]
        assert len(high_severity) >= 1

    def test_safe_module_returns_empty(self):
        """Module without deprecated PQC paths should return empty findings."""
        import tests.fixtures.safe_module as safe_mod
        result = harden_check_unsafe_api(safe_mod)
        assert result["count"] == 0
        assert result["findings"] == []


class TestHardenEdgeCase31:
    """Edge case 31: File-path target (.py file)."""

    def test_file_path_target(self):
        """Passing a .py file path should AST-walk that file."""
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "unsafe_module.py")
        result = harden_check_unsafe_api(fixture_path)
        assert result["count"] >= 1
        for finding in result["findings"]:
            assert finding["file"] == fixture_path or os.path.basename(finding["file"]) == "unsafe_module.py"

    def test_file_path_safe_module(self):
        """Safe module via file path should return empty."""
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "safe_module.py")
        result = harden_check_unsafe_api(fixture_path)
        assert result["count"] == 0


class TestHardenEdgeCase32:
    """Edge case 32: Directory target (recursive *.py walk)."""

    def test_directory_target(self):
        """Passing a directory should recursively walk *.py files."""
        fixture_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        result = harden_check_unsafe_api(fixture_dir)
        # Should find both unsafe_module.py (findings) and safe_module.py (no findings)
        assert result["count"] >= 1
        # All findings should have file pointing to a file in the fixtures directory
        for finding in result["findings"]:
            assert os.path.dirname(finding["file"]) == fixture_dir or fixture_dir in finding["file"]


class TestHardenEdgeCase33:
    """Edge case 33: Non-existent path → ValueError naming the target string."""

    def test_nonexistent_path_raises_valueerror(self):
        """Non-existent file or directory should raise ValueError with the target string."""
        with pytest.raises(ValueError) as exc_info:
            harden_check_unsafe_api("/nonexistent/path/that/does/not/exist.py")
        assert "/nonexistent/path/that/does/not/exist.py" in str(exc_info.value)

    def test_nonexistent_directory_raises_valueerror(self):
        """Non-existent directory should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            harden_check_unsafe_api("/nonexistent/directory")
        assert "/nonexistent/directory" in str(exc_info.value)


class TestHardenEdgeCase34:
    """Edge case 34: Unresolvable module name → ValueError naming the target string."""

    def test_unresolvable_module_name_raises_valueerror(self):
        """Unimportable module name should raise ValueError (not ImportError, not empty)."""
        with pytest.raises(ValueError) as exc_info:
            harden_check_unsafe_api("completely.unresolvable.module.name.that.does.not.exist")
        assert "completely.unresolvable.module.name.that.does.not.exist" in str(exc_info.value)


class TestHardenModuleObjectFileField:
    """Module-object callers get file = module.__file__ or '<memory>'."""

    def test_module_object_has_file_field(self):
        """Module object input should populate finding.file with module.__file__."""
        import tests.fixtures.unsafe_module as unsafe_mod
        result = harden_check_unsafe_api(unsafe_mod)
        assert result["count"] >= 1
        for finding in result["findings"]:
            assert finding["file"] == unsafe_mod.__file__ or finding["file"] == "<memory>"


class TestHardenSpecificPatterns:
    """Test specific deprecated patterns flagged per spec §1.2."""

    def test_flags_legacy_rsa_import(self):
        """Import of legacy RSA should be flagged."""
        # Create a temp module with RSA import
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import rsa\n")
            f.write("def foo():\n    return rsa.generate_private_key(65537, 2048)\n")
            temp_path = f.name
        try:
            result = harden_check_unsafe_api(temp_path)
            assert result["count"] >= 1
            patterns = [f["pattern"] for f in result["findings"]]
            assert any("rsa" in p.lower() for p in patterns)
        finally:
            os.unlink(temp_path)

    def test_flags_legacy_ec_import(self):
        """Import of legacy EC should be flagged."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import ec\n")
            f.write("def foo():\n    return ec.generate_private_key(ec.SECP256R1())\n")
            temp_path = f.name
        try:
            result = harden_check_unsafe_api(temp_path)
            assert result["count"] >= 1
            patterns = [f["pattern"] for f in result["findings"]]
            assert any("ec" in p.lower() or "elliptic" in p.lower() for p in patterns)
        finally:
            os.unlink(temp_path)

    def test_allows_pqc_mlkem_import(self):
        """ML-KEM import should NOT be flagged (it's PQC-ready)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import mlkem\n")
            f.write("def foo():\n    return mlkem.MLKEM768()\n")
            temp_path = f.name
        try:
            result = harden_check_unsafe_api(temp_path)
            # ML-KEM is PQC-ready, should not be flagged
            assert result["count"] == 0
        finally:
            os.unlink(temp_path)

    def test_allows_pqc_mldsa_import(self):
        """ML-DSA import should NOT be flagged (it's PQC-ready)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import mldsa\n")
            f.write("def foo():\n    return mldsa.MLDSA65()\n")
            temp_path = f.name
        try:
            result = harden_check_unsafe_api(temp_path)
            # ML-DSA is PQC-ready, should not be flagged
            assert result["count"] == 0
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])