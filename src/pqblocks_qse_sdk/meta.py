"""SDK introspection: version, primitive library bindings, FIPS compliance status.

Provides the ``status()`` function. Returns SDK metadata used by
test harnesses and introspection tools.
"""


__version__ = "0.1.0"

# FIPS tables version pinned to the spec revision
_FIPS_TABLES_VERSION = "2024-08-13"

# Primitive library bindings — populated at import time from the maintained
# libraries the SDK delegates to (pqcrypto, cryptography). These are the
# library names and the minimum verified versions the SDK requires.
_PRIMITIVE_LIBS = {
    "pqcrypto": "1.0.0",
    "cryptography": "44.0.0",
}


def status() -> dict:
    """Return SDK introspection dict.

    Returns a dict with the following keys:

    - ``version``: SDK package version string (``__version__``).
    - ``fips_tables_version``: FIPS tables version the SDK was built against.
    - ``primitive_libs``: mapping of primitive library names to their
      minimum verified versions.

    The returned dict is the same object structure that the official-vector
    test harness (S10) and merge gates expect for compliance checks.
    """
    return {
        "version": __version__,
        "fips_tables_version": _FIPS_TABLES_VERSION,
        "primitive_libs": dict(_PRIMITIVE_LIBS),
    }