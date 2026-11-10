"""
S1 test: verify src/pqblocks-qse-sdk/__main__.py exists with a main() entry point.

S1 contract rejects if this module is absent: pyproject.toml declares
``[project.scripts] pqblocks-qse-sdk = "pqblocks-qse-sdk.__main__:main"``, so the console script
target and `python -m pqblocks-qse-sdk` both resolve here. Note: the CLI subcommands
(status / corpus / matrix / harden) are wired in feature S15 — this feature
only proves the module and the callable exist.
"""
import importlib
import pathlib
import runpy
import sys


def test_main_module_file_exists():
    """src/pqblocks_qse_sdk/__main__.py must exist under the package (in repo or installed)."""
    p = pathlib.Path(__file__).parent.parent / "src" / "pqblocks_qse_sdk" / "__main__.py"
    if p.exists():
        return
    import importlib.util
    spec = importlib.util.find_spec("pqblocks_qse_sdk.__main__")
    assert spec is not None and spec.origin and pathlib.Path(spec.origin).exists(), "src/pqblocks_qse_sdk/__main__.py missing"


def test_main_callable_exists():
    """pqblocks_qse_sdk.__main__ must expose a callable main()."""
    mod = importlib.import_module("pqblocks_qse_sdk.__main__")
    assert hasattr(mod, "main"), "pqblocks_qse_sdk.__main__ has no main()"
    assert callable(mod.main), "pqblocks_qse_sdk.__main__.main is not callable"


def test_dash_m_module_invocation_has_no_invoke_error():
    """python -m pqblocks-qse-sdk (no args) must not raise SystemExit on the invoke path.

    runpy raises SystemExit only for a nonzero exit code, so this proves
    the module's __main__ plumbing is intact. argparse-level help/usage
    behaviour (exit codes 0/1/2, subcommand handling) belongs to S15.
    """
    try:
        runpy.run_module("pqblocks_qse_sdk", run_name="__main__", alter_sys=False)
    except SystemExit as exc:  # pragma: no cover - depends on S15 CLI text
        raise AssertionError(
            f"python -m qse exited with {exc.code}"
        ) from exc


if __name__ == "__main__":
    import pytest

    # Guard: sys.path must resolve the package src/ layout (see also conftest).
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
    pytest.main([__file__, "-v"])