"""
db.py — intentionally vulnerable database module.

Flaws planted here:
  - SQL injection via string formatting  (OWASP A03:2021 Injection)
"""

import sqlite3


def get_connection() -> sqlite3.Connection:
    """Return an in-memory SQLite connection pre-populated with demo data."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')")
    conn.commit()
    return conn


def find_user(username: str) -> list:
    """Look up a user by name.

    FLAW: user input is embedded directly into the SQL string — SQL injection.
    """
    conn = get_connection()
    # FLAW: f-string interpolation passed directly into execute — SQL injection
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
