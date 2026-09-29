"""
sentinel/explainer.py — maps each Finding to a plain-English explanation.

Called after the scanner to populate Finding.explanation with:
  - What the vulnerability is
  - Why it is dangerous
  - Concrete remediation steps
"""

from sentinel.models import Finding


# Map rule_id -> (title, explanation template)
_EXPLANATIONS: dict = {
    "HARDCODED_SECRET": (
        "Hardcoded Credential / Secret",
        (
            "A secret value (password, key, or token) is embedded directly in "
            "source code. Anyone with read access to the repository — including "
            "version-control history — can retrieve the secret permanently, even "
            "after it is rotated in the live system.\n\n"
            "Remediation: Load secrets from environment variables (os.getenv) or "
            "a dedicated secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). "
            "Rotate the leaked credential immediately."
        ),
    ),
    "SQL_INJECTION": (
        "SQL Injection",
        (
            "User-controlled input is concatenated directly into a SQL statement. "
            "An attacker can craft a payload such as `' OR '1'='1` to bypass "
            "authentication, dump the entire database, or (on some engines) "
            "execute arbitrary OS commands.\n\n"
            "Remediation: Always use parameterized queries — pass values as the "
            "second argument to cursor.execute(), never as part of the SQL string. "
            "Example: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
        ),
    ),
    "COMMAND_INJECTION": (
        "OS Command Injection",
        (
            "A shell command is constructed with user-supplied input and executed "
            "with shell=True. An attacker can append shell metacharacters "
            "(`;`, `|`, `&&`) to run arbitrary commands on the host with the "
            "privileges of the application process.\n\n"
            "Remediation: Pass a list of arguments to subprocess.run() and set "
            "shell=False (the default). Validate and allowlist the input before "
            "using it even in list form."
        ),
    ),
    "PATH_TRAVERSAL": (
        "Path Traversal",
        (
            "A file path is constructed from user input without validation. "
            "A payload such as `../../etc/passwd` can escape the intended "
            "directory and expose arbitrary files on the system.\n\n"
            "Remediation: After constructing the path with os.path.join(), call "
            "os.path.realpath() and assert that the result starts with the "
            "expected base directory. Reject requests that fail the check."
        ),
    ),
    "WEAK_CRYPTO": (
        "Weak Cryptographic Hash",
        (
            "MD5 and SHA-1 are collision-vulnerable and far too fast for "
            "password hashing — a modern GPU can test billions of candidates "
            "per second, making offline dictionary attacks trivial.\n\n"
            "Remediation: Use bcrypt, scrypt, or argon2 (via the `bcrypt` or "
            "`argon2-cffi` library) for passwords. For general-purpose checksums "
            "where collision resistance matters, use SHA-256 or SHA-3."
        ),
    ),
}


def explain(finding: Finding) -> Finding:
    """Populate finding.explanation in-place and return the finding."""
    title, body = _EXPLANATIONS.get(
        finding.rule_id,
        ("Unknown Rule", "No explanation available for this rule."),
    )
    finding.explanation = f"## {title}\n\n{body}"
    return finding


def explain_all(findings: list[Finding]) -> list[Finding]:
    """Explain every finding in the list and return the same list."""
    for f in findings:
        explain(f)
    return findings
