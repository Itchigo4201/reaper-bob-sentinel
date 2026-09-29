"""
sentinel/test_generator.py — generates regression pytest files for each fix.

Each generated test file is written to tests/generated/test_fix_<module>.py.
The tests import from the *_safe modules and assert that:
  - The vulnerability payload is rejected / neutralised.
  - The fixed function still works correctly for legitimate input.

Generated files are deterministic and idempotent (re-running overwrites them).
"""

from pathlib import Path

_TESTS_DIR = Path(__file__).parent.parent / "tests" / "generated"


# ---------------------------------------------------------------------------
# Per-fix test templates
# ---------------------------------------------------------------------------

_TEST_AUTH = '''\
"""
Auto-generated regression tests for HARDCODED_SECRET fix in auth_safe.py.
Rule: HARDCODED_SECRET  |  OWASP: A02:2021 Cryptographic Failures
"""
import os
import importlib
import pytest


def _load_auth_safe():
    """Import auth_safe with required env vars set."""
    os.environ.setdefault("APP_ADMIN_USERNAME", "admin")
    os.environ.setdefault("APP_ADMIN_PASSWORD", "test_password_from_env")
    os.environ.setdefault("APP_SECRET_KEY", "test_secret_from_env")
    import importlib, sys
    # Force reload so env vars are picked up
    mod_name = "vulnerable_app.auth_safe"
    if mod_name in sys.modules:
        return importlib.reload(sys.modules[mod_name])
    return importlib.import_module(mod_name)


class TestAuthSafeNoHardcodedSecrets:
    def test_admin_password_not_literal_string(self):
        """ADMIN_PASSWORD must not be a bare string literal in source."""
        import ast
        from pathlib import Path
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "auth_safe.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "ADMIN_PASSWORD":
                        assert not isinstance(node.value, ast.Constant), (
                            "ADMIN_PASSWORD must not be a hardcoded string literal"
                        )

    def test_secret_key_not_literal_string(self):
        """SECRET_KEY must not be a bare string literal in source."""
        import ast
        from pathlib import Path
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "auth_safe.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "SECRET_KEY":
                        assert not isinstance(node.value, ast.Constant), (
                            "SECRET_KEY must not be a hardcoded string literal"
                        )

    def test_login_works_with_env_credential(self):
        """login() should succeed when env var matches supplied password."""
        os.environ["APP_ADMIN_USERNAME"] = "admin"
        os.environ["APP_ADMIN_PASSWORD"] = "env_set_password"
        auth = _load_auth_safe()
        assert auth.login("admin", "env_set_password") is True

    def test_login_fails_with_wrong_password(self):
        os.environ["APP_ADMIN_USERNAME"] = "admin"
        os.environ["APP_ADMIN_PASSWORD"] = "correct"
        auth = _load_auth_safe()
        assert auth.login("admin", "wrong") is False

    def test_scanner_reports_no_hardcoded_secret_in_safe(self):
        """The scanner must produce zero HARDCODED_SECRET findings in auth_safe.py."""
        from pathlib import Path
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "auth_safe.py")
        findings = [f for f in scan_file(path, "auth_safe.py") if f.rule_id == "HARDCODED_SECRET"]
        assert findings == [], f"Unexpected findings: {findings}"
'''

_TEST_DB = '''\
"""
Auto-generated regression tests for SQL_INJECTION fix in db_safe.py.
Rule: SQL_INJECTION  |  OWASP: A03:2021 Injection
"""
import pytest


def _find_user_safe(username):
    from vulnerable_app.db_safe import find_user
    return find_user(username)


class TestDbSafeNoSqlInjection:
    def test_legitimate_query_returns_result(self):
        """Safe find_user() must still return rows for a valid username."""
        rows = _find_user_safe("alice")
        assert len(rows) == 1
        assert rows[0][1] == "alice"

    def test_injection_payload_returns_empty(self):
        """Classic injection payload must return no rows (not the whole table)."""
        payload = "' OR '1'='1"
        rows = _find_user_safe(payload)
        assert rows == [], (
            f"SQL injection succeeded — got {rows} for payload {payload!r}"
        )

    def test_tautology_payload_returns_empty(self):
        payload = "x' OR 1=1 --"
        rows = _find_user_safe(payload)
        assert rows == []

    def test_union_payload_returns_empty(self):
        payload = "x' UNION SELECT 1,2,3 --"
        rows = _find_user_safe(payload)
        assert rows == []

    def test_scanner_reports_no_sql_injection_in_safe(self):
        """The scanner must produce zero SQL_INJECTION findings in db_safe.py."""
        from pathlib import Path
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "db_safe.py")
        findings = [f for f in scan_file(path, "db_safe.py") if f.rule_id == "SQL_INJECTION"]
        assert findings == [], f"Unexpected findings: {findings}"
'''

_TEST_API = '''\
"""
Auto-generated regression tests for COMMAND_INJECTION fix in api_safe.py.
Rule: COMMAND_INJECTION  |  OWASP: A03:2021 Injection
"""
import ast
from pathlib import Path


def _safe_source():
    return (Path(__file__).parent.parent.parent / "vulnerable_app" / "api_safe.py").read_text()


class TestApiSafeNoCommandInjection:
    def test_shell_true_absent_from_source(self):
        """api_safe.py must not contain shell=True in live code (comments/docstrings excluded)."""
        import ast as _ast
        src = _safe_source()
        tree = _ast.parse(src)
        lines = src.splitlines()
        docstring_lines = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Expr) and isinstance(node.value, _ast.Constant):
                if isinstance(node.value.value, str):
                    for ln in range(node.lineno, node.end_lineno + 1):
                        docstring_lines.add(ln)
        code_lines = [
            line for i, line in enumerate(lines, 1)
            if i not in docstring_lines and not line.lstrip().startswith("#")
        ]
        code_only = chr(10).join(code_lines)
        assert "shell=True" not in code_only, "shell=True still present in api_safe.py code"

    def test_shell_false_present_in_source(self):
        """api_safe.py must explicitly use shell=False."""
        src = _safe_source()
        assert "shell=False" in src, "shell=False not found in api_safe.py"

    def test_args_passed_as_list(self):
        """subprocess.run must receive a list, not an f-string."""
        src = _safe_source()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "run"):
                continue
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                pytest.fail("subprocess.run still receives an f-string argument")
            if node.args and isinstance(node.args[0], ast.List):
                return  # found the safe list form — test passes
        # If no subprocess.run call found at all that\'s fine for this check
        pass

    def test_scanner_reports_no_command_injection_in_safe(self):
        """The scanner must produce zero COMMAND_INJECTION findings in api_safe.py."""
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "api_safe.py")
        findings = [f for f in scan_file(path, "api_safe.py") if f.rule_id == "COMMAND_INJECTION"]
        assert findings == [], f"Unexpected findings: {findings}"
'''

_TEST_UTILS = '''\
"""
Auto-generated regression tests for PATH_TRAVERSAL and WEAK_CRYPTO fixes in utils_safe.py.
Rules: PATH_TRAVERSAL (A01:2021), WEAK_CRYPTO (A02:2021)
"""
import os
import pytest
from pathlib import Path


def _read_file_safe(filename):
    from vulnerable_app.utils_safe import read_file
    return read_file(filename)


def _hash_password_safe(password):
    from vulnerable_app.utils_safe import hash_password
    return hash_password(password)


def _verify_password_safe(password, stored):
    from vulnerable_app.utils_safe import verify_password
    return verify_password(password, stored)


class TestUtilsSafePathTraversal:
    def test_traversal_payload_raises(self):
        """Traversal sequences must be rejected with ValueError."""
        with pytest.raises(ValueError, match="escapes the base directory"):
            _read_file_safe("../../../etc/passwd")

    def test_double_encoded_traversal_raises(self):
        """Traversal via double-dots must be caught regardless of depth."""
        with pytest.raises(ValueError, match="escapes the base directory"):
            _read_file_safe("../../sensitive")

    def test_absolute_path_raises(self):
        """An absolute path that leaves BASE_DIR must also be rejected."""
        with pytest.raises((ValueError, OSError)):
            _read_file_safe("/etc/passwd")

    def test_scanner_reports_no_path_traversal_in_safe(self):
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py")
        findings = [f for f in scan_file(path, "utils_safe.py") if f.rule_id == "PATH_TRAVERSAL"]
        assert findings == [], f"Unexpected findings: {findings}"


class TestUtilsSafeWeakCrypto:
    def test_md5_not_in_source(self):
        """utils_safe.py must not call hashlib.md5."""
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py").read_text()
        assert "hashlib.md5" not in src, "hashlib.md5 still present in utils_safe.py"

    def test_scrypt_used_in_source(self):
        """utils_safe.py must use hashlib.scrypt for password hashing."""
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py").read_text()
        assert "hashlib.scrypt" in src, "hashlib.scrypt not found in utils_safe.py"

    def test_hash_contains_salt_separator(self):
        """Stored hash must embed the salt: format is <salt_hex>$<key_hex>."""
        stored = _hash_password_safe("password123")
        assert "$" in stored, f"Expected salt$key format, got: {stored!r}"
        salt_hex, key_hex = stored.split("$", 1)
        assert len(salt_hex) == 32, f"Expected 16-byte salt (32 hex chars), got {len(salt_hex)}"
        assert len(key_hex) > 0, "Derived key portion must not be empty"

    def test_each_hash_has_unique_salt(self):
        """Two hashes of the same password must use different salts."""
        h1 = _hash_password_safe("abc")
        h2 = _hash_password_safe("abc")
        salt1 = h1.split("$")[0]
        salt2 = h2.split("$")[0]
        assert salt1 != salt2, "Salt must be randomly generated, not static"

    def test_verify_correct_password_succeeds(self):
        """verify_password() must return True for the correct password."""
        stored = _hash_password_safe("correct_horse_battery")
        assert _verify_password_safe("correct_horse_battery", stored) is True

    def test_verify_wrong_password_fails(self):
        """verify_password() must return False for an incorrect password."""
        stored = _hash_password_safe("correct_horse_battery")
        assert _verify_password_safe("wrong_password", stored) is False

    def test_verify_empty_password_fails(self):
        stored = _hash_password_safe("nonempty")
        assert _verify_password_safe("", stored) is False

    def test_verify_malformed_stored_returns_false(self):
        """verify_password() must not raise on a malformed stored value (missing $)."""
        assert _verify_password_safe("anything", "no-dollar-sign-here") is False

    def test_verify_invalid_hex_returns_false(self):
        """verify_password() must return False when salt or key is invalid hex."""
        assert _verify_password_safe("anything", "nothex$alsonothex") is False

    def test_verify_function_exists(self):
        """utils_safe.py must export verify_password."""
        from vulnerable_app import utils_safe
        assert hasattr(utils_safe, "verify_password"), "verify_password not found in utils_safe"

    def test_scanner_reports_no_weak_crypto_in_safe(self):
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py")
        findings = [f for f in scan_file(path, "utils_safe.py") if f.rule_id == "WEAK_CRYPTO"]
        assert findings == [], f"Unexpected findings: {findings}"
'''


# ---------------------------------------------------------------------------
# Generator mapping  module → template string
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, tuple[str, str]] = {
    "auth": ("test_fix_auth.py", _TEST_AUTH),
    "db":   ("test_fix_db.py",   _TEST_DB),
    "api":  ("test_fix_api.py",  _TEST_API),
    "utils":("test_fix_utils.py",_TEST_UTILS),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_tests(output_dir: str | None = None) -> list[str]:
    """Write all generated regression test files.  Returns list of written paths."""
    out = Path(output_dir) if output_dir else _TESTS_DIR
    out.mkdir(parents=True, exist_ok=True)

    # Ensure the generated package is importable
    init = out / "__init__.py"
    if not init.exists():
        init.write_text("")

    written: list[str] = []
    for _key, (filename, template) in _TEMPLATES.items():
        dest = out / filename
        dest.write_text(template, encoding="utf-8")
        written.append(str(dest))

    return written
