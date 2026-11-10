"""S4 — sizes.py must match FIPS 203/204/205 Table 2 exactly.

RED evidence (ground truth from brief/references/fips-205-pdftotext.txt, line
2243-2256, plus pqcrypto's own output for every parameter set):

  SLH-DSA     n   pk bytes   sig bytes   (FIPS 205 Table 2 "security/pk/sig")
  SHA2-128s   16     32        7856
  SHA2-128f   16     32       17088
  SHA2-192s   24     48       16224
  SHA2-192f   24     48       35664
  SHA2-256s   32     64       29792
  SHA2-256f   32     64       49856

src/pqblocks-qse-sdk/sizes.py currently stores 10800 / 11400 / 13680 / 13680 for the 192/256
parameter sets, which contradicts both the FIPS table AND pqcrypto's own
output AND src/pqblocks-qse-sdk/sign.py. Those values are wrong and must be corrected.

This test file is the regression guard: it fails now, and after the fix it
passes.
"""

import pytest

from pqblocks_qse_sdk.sizes import get_size


# Ground truth for SLH-DSA (FIPS 205 Table 2, verified verbatim from the local
# pdftotext extraction and confirmed against pqcrypto's actual output).
SLH_DSA_FIPS205 = {
    "slh-dsa-sha2-128s": {"pk_len": 32, "sk_len": 64, "sig_len": 7856},
    "slh-dsa-sha2-128f": {"pk_len": 32, "sk_len": 64, "sig_len": 17088},
    "slh-dsa-sha2-192s": {"pk_len": 48, "sk_len": 96, "sig_len": 16224},
    "slh-dsa-sha2-192f": {"pk_len": 48, "sk_len": 96, "sig_len": 35664},
    "slh-dsa-sha2-256s": {"pk_len": 64, "sk_len": 128, "sig_len": 29792},
    "slh-dsa-sha2-256f": {"pk_len": 64, "sk_len": 128, "sig_len": 49856},
    "slh-dsa-shake-128s": {"pk_len": 32, "sk_len": 64, "sig_len": 7856},
    "slh-dsa-shake-128f": {"pk_len": 32, "sk_len": 64, "sig_len": 17088},
    "slh-dsa-shake-192s": {"pk_len": 48, "sk_len": 96, "sig_len": 16224},
    "slh-dsa-shake-192f": {"pk_len": 48, "sk_len": 96, "sig_len": 35664},
    "slh-dsa-shake-256s": {"pk_len": 64, "sk_len": 128, "sig_len": 29792},
    "slh-dsa-shake-256f": {"pk_len": 64, "sk_len": 128, "sig_len": 49856},
}


@pytest.mark.parametrize("algorithm", sorted(SLH_DSA_FIPS205))
def test_sizes_matches_fips205_table_2(algorithm):
    """Every SLH-DSA parameter set's sig_len must equal FIPS 205 Table 2."""
    expected = SLH_DSA_FIPS205[algorithm]
    actual = get_size(algorithm, "sig_len")
    assert actual == expected["sig_len"], (
        f"{algorithm}: sizes.py has sig_len={actual}, "
        f"FIPS 205 Table 2 says {expected['sig_len']}"
    )


def test_sizes_matches_sign_facade():
    """sizes.py and sign.py must agree — two tables diverging is a defect."""
    import sys

    sign_facade = sys.modules["pqblocks_qse_sdk.sign"]

    for qse_name in sorted(SLH_DSA_FIPS205):
        module = sign_facade._SIGN_MODULES[qse_name]
        pk, sk = module.keygen()
        sig = module.sign(sk, b"conformance")
        assert get_size(qse_name, "sig_len") == len(sig), (
            f"{qse_name}: sizes.py has {get_size(qse_name, 'sig_len')}, "
            f"pqcrypto produces {len(sig)}"
        )
