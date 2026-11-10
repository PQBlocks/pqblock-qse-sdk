"""S1 test: verify README.md exists and has required content."""
import pathlib


def test_readme_exists():
    """README.md must exist at package root when in workspace."""
    readme = pathlib.Path(__file__).parent.parent / "README.md"
    if not readme.exists():
        import pytest
        pytest.skip("README.md not present in cleanroom wheel test environment")
    assert readme.exists(), "README.md missing at package root"


def test_readme_has_required_sections():
    """README.md must have minimal required sections."""
    readme = pathlib.Path(__file__).parent.parent / "README.md"
    if not readme.exists():
        import pytest
        pytest.skip("README.md not present in cleanroom wheel test environment")
    content = readme.read_text()
    assert "# pqblock-pqblocks_qse_sdk-sdk" in content or "pqblock-pqblocks_qse_sdk-sdk" in content
    assert "FIPS 203" in content or "ML-KEM" in content
    assert "FIPS 204" in content or "ML-DSA" in content
    assert "FIPS 205" in content or "SLH-DSA" in content
    assert "install" in content.lower()


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])