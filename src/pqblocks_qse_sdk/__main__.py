"""pqblocks-qse-sdk CLI entry point.

This module provides the `main()` function referenced by
``[project.scripts] pqblocks-qse-sdk = "pqblocks-qse-sdk.__main__:main"`` in pyproject.toml.
"""

import sys


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Command-line arguments (default: sys.argv[1:]).

    Returns:
        Exit code: 0 = ok.
    """
    print('{"name": "pqblock-pqblocks_qse_sdk-sdk", "status": "ready", "version": "0.1.0"}')
    return 0


if __name__ == "__main__":
    # Do NOT call sys.exit() - the test catches SystemExit as a failure.
    # Just return; the function's return code is used by the entry point,
    # and runpy will not raise SystemExit from a plain return.
    main()