"""
utils.py — intentionally vulnerable utility helpers.

Flaws planted here:
  - Path traversal via unsanitised user-supplied filename  (OWASP A01:2021 Broken Access Control)
  - Weak MD5 hashing used for passwords                   (OWASP A02:2021 Cryptographic Failures)
"""

import hashlib
import os


BASE_DIR = "/var/app/uploads"


def read_file(filename: str) -> str:
    """Read and return the contents of a file from BASE_DIR.

    FLAW: filename is not validated — a caller can supply '../../../etc/passwd'
    and escape BASE_DIR entirely.
    """
    # FIX: resolve the real path and assert it stays within BASE_DIR
    path = os.path.realpath(os.path.join(BASE_DIR, filename))
    base = os.path.realpath(BASE_DIR)
    if not path.startswith(base + os.sep) and path != base:
        raise ValueError(f"Access denied: '{filename}' escapes the base directory")
    with open(path) as fh:
        return fh.read()


def hash_password(password: str) -> str:
    """Return a scrypt-derived key with an embedded random salt.

    Format: "<salt_hex>$<derived_key_hex>"
    The salt is 16 bytes of os.urandom; scrypt parameters are
    n=2**14, r=8, p=1 (OWASP-recommended minimum for interactive logins).
    """
    # FIX: scrypt password KDF with random salt (hashlib stdlib, Python 3.6+)
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    """Return True iff password matches the stored scrypt hash.

    Uses hmac.compare_digest to prevent timing attacks.
    """
    import hmac
    try:
        salt_hex, key_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        bytes.fromhex(key_hex)  # validate key is valid hex before deriving
    except ValueError:
        return False
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(dk.hex(), key_hex)
