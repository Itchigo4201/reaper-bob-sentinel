"""
sentinel/fixer.py — produces fixed (_safe) versions of each vulnerable module.

Strategy
--------
Each fix is a self-contained function that accepts the source of a vulnerable
module as a string and returns the patched source as a string.  The top-level
apply_fixes() function drives the process:

  1. Reads the original vulnerable_app/<module>.py
  2. Applies the fix function
  3. Writes the result to vulnerable_app/<module>_safe.py

The originals are never modified, so the before/after diff is always visible.

Fix inventory (one per detected finding rule)
---------------------------------------------
  auth.py      HARDCODED_SECRET  × 2  → load from os.environ
  db.py        SQL_INJECTION          → parameterized query
  api.py       COMMAND_INJECTION      → list args + shell=False
  utils.py     PATH_TRAVERSAL         → realpath containment check
  utils.py     WEAK_CRYPTO            → hashlib.scrypt KDF, random salt, verify_password()
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Callable

from sentinel.models import Finding


_APP_DIR = Path(__file__).parent.parent / "vulnerable_app"


# ---------------------------------------------------------------------------
# Individual fix functions  (str → str)
# ---------------------------------------------------------------------------

def _fix_auth(source: str) -> str:
    """Replace hardcoded credentials and secret key with os.environ lookups."""
    # Ensure os is imported
    if "import os" not in source:
        source = "import os\n" + source

    source = re.sub(
        r'^(ADMIN_USERNAME\s*=\s*)".+"',
        r'ADMIN_USERNAME = os.environ.get("APP_ADMIN_USERNAME", "admin")',
        source,
        flags=re.MULTILINE,
    )
    source = re.sub(
        r'^(ADMIN_PASSWORD\s*=\s*)".+"',
        r'ADMIN_PASSWORD = os.environ.get("APP_ADMIN_PASSWORD")',
        source,
        flags=re.MULTILINE,
    )
    source = re.sub(
        r'^(SECRET_KEY\s*=\s*)".+"',
        r'SECRET_KEY = os.environ.get("APP_SECRET_KEY")',
        source,
        flags=re.MULTILINE,
    )
    return source


def _fix_db(source: str) -> str:
    """Replace f-string SQL concatenation with a parameterized query."""
    source = re.sub(
        r'conn\.execute\(f"SELECT \* FROM users WHERE username = \'\{username\}\'"\)',
        'conn.execute("SELECT * FROM users WHERE username = ?", (username,))',
        source,
    )
    return source


def _fix_api(source: str) -> str:
    """Replace shell=True with a safe argument list."""
    # Replace the dangerous call block with a safe equivalent
    old = (
        '    result = subprocess.run(\n'
        '        f"ping -c 1 {host}",\n'
        '        shell=True,\n'
        '        capture_output=True,\n'
        '        text=True,\n'
        '    )'
    )
    new = (
        '    # FIX: pass args as a list and keep shell=False (default)\n'
        '    result = subprocess.run(\n'
        '        ["ping", "-c", "1", host],\n'
        '        shell=False,\n'
        '        capture_output=True,\n'
        '        text=True,\n'
        '    )'
    )
    return source.replace(old, new)


def _fix_utils(source: str) -> str:
    """Fix path traversal and replace MD5 with scrypt-based password KDF."""
    # --- PATH TRAVERSAL fix ---
    old_read = (
        '    # FLAW: no normalisation or containment check\n'
        '    path = os.path.join(BASE_DIR, filename)\n'
        '    with open(path) as fh:\n'
        '        return fh.read()'
    )
    new_read = (
        '    # FIX: resolve the real path and assert it stays within BASE_DIR\n'
        '    path = os.path.realpath(os.path.join(BASE_DIR, filename))\n'
        '    base = os.path.realpath(BASE_DIR)\n'
        '    if not path.startswith(base + os.sep) and path != base:\n'
        '        raise ValueError(f"Access denied: \'{filename}\' escapes the base directory")\n'
        '    with open(path) as fh:\n'
        '        return fh.read()'
    )
    source = source.replace(old_read, new_read)

    # --- WEAK CRYPTO fix ---
    # Replace the entire hash_password function and add verify_password.
    # The replacement uses hashlib.scrypt (stdlib, Python 3.6+):
    #   - 16-byte cryptographically random salt per call
    #   - salt and derived key stored as "salt_hex$key_hex"
    #   - verify_password() re-derives and compares in constant time
    old_hash_func = (
        'def hash_password(password: str) -> str:\n'
        '    """Return a hash of the supplied password.\n'
        '\n'
        '    FLAW: MD5 is cryptographically broken and must not be used for passwords.\n'
        '    """\n'
        '    # FLAW: MD5 is not suitable for password hashing\n'
        '    return hashlib.md5(password.encode()).hexdigest()'
    )
    new_hash_func = (
        'def hash_password(password: str) -> str:\n'
        '    """Return a scrypt-derived key with an embedded random salt.\n'
        '\n'
        '    Format: "<salt_hex>$<derived_key_hex>"\n'
        '    The salt is 16 bytes of os.urandom; scrypt parameters are\n'
        '    n=2**14, r=8, p=1 (OWASP-recommended minimum for interactive logins).\n'
        '    """\n'
        '    # FIX: scrypt password KDF with random salt (hashlib stdlib, Python 3.6+)\n'
        '    salt = os.urandom(16)\n'
        '    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)\n'
        '    return salt.hex() + "$" + dk.hex()\n'
        '\n'
        '\n'
        'def verify_password(password: str, stored: str) -> bool:\n'
        '    """Return True iff password matches the stored scrypt hash.\n'
        '\n'
        '    Uses hmac.compare_digest to prevent timing attacks.\n'
        '    """\n'
        '    import hmac\n'
        '    try:\n'
        '        salt_hex, key_hex = stored.split("$", 1)\n'
        '        salt = bytes.fromhex(salt_hex)\n'
        '        bytes.fromhex(key_hex)  # validate key is valid hex before deriving\n'
        '    except ValueError:\n'
        '        return False\n'
        '    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)\n'
        '    return hmac.compare_digest(dk.hex(), key_hex)'
    )
    source = source.replace(old_hash_func, new_hash_func)

    return source


# ---------------------------------------------------------------------------
# Fix registry
# ---------------------------------------------------------------------------

@dataclass
class FixEntry:
    module: str              # source filename, e.g. "auth.py"
    safe_module: str         # output filename, e.g. "auth_safe.py"
    apply: Callable          # fix function
    rule_ids: list           # which rule_ids this fix addresses
    description: str         # human-readable summary


_FIXES: list[FixEntry] = [
    FixEntry(
        module="auth.py",
        safe_module="auth_safe.py",
        apply=_fix_auth,
        rule_ids=["HARDCODED_SECRET"],
        description="Load credentials and secret key from environment variables",
    ),
    FixEntry(
        module="db.py",
        safe_module="db_safe.py",
        apply=_fix_db,
        rule_ids=["SQL_INJECTION"],
        description="Use parameterized SQL query instead of f-string interpolation",
    ),
    FixEntry(
        module="api.py",
        safe_module="api_safe.py",
        apply=_fix_api,
        rule_ids=["COMMAND_INJECTION"],
        description="Pass arguments as a list to subprocess.run with shell=False",
    ),
    FixEntry(
        module="utils.py",
        safe_module="utils_safe.py",
        apply=_fix_utils,
        rule_ids=["PATH_TRAVERSAL", "WEAK_CRYPTO"],
        description="Validate path containment; replace MD5 with scrypt KDF + verify_password()",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class FixResult:
    entry: FixEntry
    source_path: str
    safe_path: str
    success: bool
    error: str = ""


def apply_fixes(app_dir: str | None = None) -> list[FixResult]:
    """Apply all fixes and write *_safe.py files.  Returns one FixResult per fix."""
    base = Path(app_dir) if app_dir else _APP_DIR
    results: list[FixResult] = []

    for entry in _FIXES:
        src_path = base / entry.module
        safe_path = base / entry.safe_module
        try:
            source = src_path.read_text(encoding="utf-8")
            fixed = entry.apply(source)
            safe_path.write_text(fixed, encoding="utf-8")
            results.append(
                FixResult(
                    entry=entry,
                    source_path=str(src_path),
                    safe_path=str(safe_path),
                    success=True,
                )
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                FixResult(
                    entry=entry,
                    source_path=str(src_path),
                    safe_path=str(safe_path),
                    success=False,
                    error=str(exc),
                )
            )

    return results
