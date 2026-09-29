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
