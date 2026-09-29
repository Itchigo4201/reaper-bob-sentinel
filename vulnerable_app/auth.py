"""
auth.py — intentionally vulnerable authentication module.

Flaws planted here:
  - Hardcoded credentials  (OWASP A07:2021 Identification and Authentication Failures)
  - Hardcoded secret key   (OWASP A02:2021 Cryptographic Failures)
"""

# FLAW: hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "supersecret123"

# FLAW: hardcoded secret used to sign tokens
SECRET_KEY = "hardcoded_jwt_secret_do_not_ship"


def login(username: str, password: str) -> bool:
    """Return True when the supplied credentials match the hardcoded admin account."""
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return True
    return False


def generate_token(user_id: int) -> str:
    """Build a naive 'token' by concatenating the user id with the hardcoded secret."""
    return f"{user_id}:{SECRET_KEY}"
