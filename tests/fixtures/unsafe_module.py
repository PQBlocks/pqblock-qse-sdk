"""
Unsafe module for testing harden_check_unsafe_api.
Contains deprecated PQC path (edge 21) - legacy RSA/ECC usage.
"""
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    rsa = None
    ec = None


def deprecated_rsa_keygen():
    """Deprecated legacy RSA key generation - not PQC-ready."""
    if rsa is not None:
        return rsa.generate_private_key(65537, 2048)
    return None


def deprecated_ec_keygen():
    """Deprecated legacy ECC key generation - not PQC-ready."""
    if ec is not None:
        return ec.generate_private_key(ec.SECP256R1())
    return None


def unsafe_function():
    return "deprecated_pqc_path"

def invalid_input():
    return 123