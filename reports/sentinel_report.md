# REAPER-Bob Sentinel — Security Report

**Generated:** 2026-09-29T01:56:51Z
**Overall status:** ✅ PASS

## Summary

| Metric | Value |
|--------|-------|
| Findings detected | 6 |
| CRITICAL | 2 |
| HIGH | 4 |
| Fixes applied | 4 |
| Scan verifications passed | 5 / 5 |
| Tests passed | 87 / 87 |

## Findings

### 1. 🔴 `COMMAND_INJECTION` — A03:2021 Injection

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **File** | `vulnerable_app/api.py` line 17 |
| **Symbol** | `subprocess.run` |
| **Message** | 'subprocess.run' called with shell=True and unsanitised input. Pass a list of arguments and set shell=False. |
| **Remediation** | Pass arguments as a list to subprocess.run with shell=False |
| **Safe file** | `vulnerable_app/api_safe.py` |
| **Verification** | ✅ `COMMAND_INJECTION` no longer detected in safe file |

**Vulnerable snippet:**
```python
result = subprocess.run(
```

<details>
<summary>Root cause &amp; remediation detail</summary>

A shell command is constructed with user-supplied input and executed with shell=True. An attacker can append shell metacharacters (`;`, `|`, `&&`) to run arbitrary commands on the host with the privileges of the application process.

Remediation: Pass a list of arguments to subprocess.run() and set shell=False (the default). Validate and allowlist the input before using it even in list form.

</details>

### 2. 🔴 `SQL_INJECTION` — A03:2021 Injection

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **File** | `vulnerable_app/db.py` line 30 |
| **Symbol** | `execute` |
| **Message** | SQL query constructed with string interpolation. Use parameterized queries (pass values as a tuple). |
| **Remediation** | Use parameterized SQL query instead of f-string interpolation |
| **Safe file** | `vulnerable_app/db_safe.py` |
| **Verification** | ✅ `SQL_INJECTION` no longer detected in safe file |

**Vulnerable snippet:**
```python
cursor = conn.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

<details>
<summary>Root cause &amp; remediation detail</summary>

User-controlled input is concatenated directly into a SQL statement. An attacker can craft a payload such as `' OR '1'='1` to bypass authentication, dump the entire database, or (on some engines) execute arbitrary OS commands.

Remediation: Always use parameterized queries — pass values as the second argument to cursor.execute(), never as part of the SQL string. Example: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))

</details>

### 3. 🟠 `HARDCODED_SECRET` — A02:2021 Cryptographic Failures

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `vulnerable_app/auth.py` line 11 |
| **Symbol** | `ADMIN_PASSWORD` |
| **Message** | Hardcoded secret assigned to 'ADMIN_PASSWORD'. Use environment variables or a secrets manager instead. |
| **Remediation** | Load credentials and secret key from environment variables |
| **Safe file** | `vulnerable_app/auth_safe.py` |
| **Verification** | ✅ `HARDCODED_SECRET` no longer detected in safe file |

**Vulnerable snippet:**
```python
ADMIN_PASSWORD = "supersecret123"
```

<details>
<summary>Root cause &amp; remediation detail</summary>

A secret value (password, key, or token) is embedded directly in source code. Anyone with read access to the repository — including version-control history — can retrieve the secret permanently, even after it is rotated in the live system.

Remediation: Load secrets from environment variables (os.getenv) or a dedicated secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). Rotate the leaked credential immediately.

</details>

### 4. 🟠 `HARDCODED_SECRET` — A02:2021 Cryptographic Failures

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `vulnerable_app/auth.py` line 14 |
| **Symbol** | `SECRET_KEY` |
| **Message** | Hardcoded secret assigned to 'SECRET_KEY'. Use environment variables or a secrets manager instead. |
| **Remediation** | Load credentials and secret key from environment variables |
| **Safe file** | `vulnerable_app/auth_safe.py` |
| **Verification** | ✅ `HARDCODED_SECRET` no longer detected in safe file |

**Vulnerable snippet:**
```python
SECRET_KEY = "hardcoded_jwt_secret_do_not_ship"
```

<details>
<summary>Root cause &amp; remediation detail</summary>

A secret value (password, key, or token) is embedded directly in source code. Anyone with read access to the repository — including version-control history — can retrieve the secret permanently, even after it is rotated in the live system.

Remediation: Load secrets from environment variables (os.getenv) or a dedicated secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). Rotate the leaked credential immediately.

</details>

### 5. 🟠 `PATH_TRAVERSAL` — A01:2021 Broken Access Control

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `vulnerable_app/utils.py` line 23 |
| **Symbol** | `os.path.join` |
| **Message** | os.path.join() receives unsanitised parameter 'filename'. Validate with os.path.realpath() and check the result stays within the base directory. |
| **Remediation** | Resolve and validate path containment within the allowed base directory |
| **Safe file** | `vulnerable_app/utils_safe.py` |
| **Verification** | ✅ `PATH_TRAVERSAL` no longer detected in safe file |

**Vulnerable snippet:**
```python
path = os.path.join(BASE_DIR, filename)
```

<details>
<summary>Root cause &amp; remediation detail</summary>

A file path is constructed from user input without validation. A payload such as `../../etc/passwd` can escape the intended directory and expose arbitrary files on the system.

Remediation: After constructing the path with os.path.join(), call os.path.realpath() and assert that the result starts with the expected base directory. Reject requests that fail the check.

</details>

### 6. 🟠 `WEAK_CRYPTO` — A02:2021 Cryptographic Failures

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **File** | `vulnerable_app/utils.py` line 34 |
| **Symbol** | `hashlib.md5` |
| **Message** | hashlib.md5() is cryptographically broken. Use scrypt/bcrypt/argon2 for passwords; use SHA-256 only for non-password hashing. |
| **Remediation** | Replace MD5 password hashing with salted scrypt and verify_password() |
| **Safe file** | `vulnerable_app/utils_safe.py` |
| **Verification** | ✅ `WEAK_CRYPTO` no longer detected in safe file |

**Vulnerable snippet:**
```python
return hashlib.md5(password.encode()).hexdigest()
```

<details>
<summary>Root cause &amp; remediation detail</summary>

MD5 and SHA-1 are collision-vulnerable and far too fast for password hashing — a modern GPU can test billions of candidates per second, making offline dictionary attacks trivial.

Remediation: Use bcrypt, scrypt, or argon2 (via the `bcrypt` or `argon2-cffi` library) for passwords. For general-purpose checksums where collision resistance matters, use SHA-256 or SHA-3.

</details>

## Verification

### Static re-scan (safe files)

| Rule | Safe file | Result |
|------|-----------|--------|
| `HARDCODED_SECRET` | `vulnerable_app/auth_safe.py` | ✅ Clean |
| `SQL_INJECTION` | `vulnerable_app/db_safe.py` | ✅ Clean |
| `COMMAND_INJECTION` | `vulnerable_app/api_safe.py` | ✅ Clean |
| `PATH_TRAVERSAL` | `vulnerable_app/utils_safe.py` | ✅ Clean |
| `WEAK_CRYPTO` | `vulnerable_app/utils_safe.py` | ✅ Clean |

### Test suite

| Result | Count |
|--------|-------|
| Passed | 87 |
| Failed | 0 |
| Total  | 87 |

**Exit code:** `0` — All tests passed.

---

*Generated by REAPER-Bob Sentinel · IBM Bob Hackathon 2026*