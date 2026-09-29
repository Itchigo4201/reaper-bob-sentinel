"""
api.py — intentionally vulnerable API helpers.

Flaws planted here:
  - OS command injection via subprocess/shell=True  (OWASP A03:2021 Injection)
"""

import subprocess


def ping_host(host: str) -> str:
    """Ping a host and return the raw output.

    FLAW: host is interpolated directly into a shell command — command injection.
    """
    # FLAW: shell=True with unsanitised user input
    # FIX: pass args as a list and keep shell=False (default)
    result = subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
    )
    return result.stdout
