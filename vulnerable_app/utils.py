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
    # FLAW: no normalisation or containment check
    path = os.path.join(BASE_DIR, filename)
    with open(path) as fh:
        return fh.read()


def hash_password(password: str) -> str:
    """Return a hash of the supplied password.

    FLAW: MD5 is cryptographically broken and must not be used for passwords.
    """
    # FLAW: MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()
