"""
tests/test_fixer.py — unit tests for sentinel.fixer and sentinel.test_generator.

These tests verify that:
  1. apply_fixes() produces all expected *_safe.py files.
  2. Each safe file is importable and the scanner no longer flags it.
  3. test_generator.generate_tests() writes the expected files.
"""

import os
import importlib
import sys
from pathlib import Path

import pytest

from sentinel.fixer import apply_fixes, _FIXES
from sentinel.scanner import scan_file
from sentinel.test_generator import generate_tests

_ROOT = Path(__file__).parent.parent
_APP = _ROOT / "vulnerable_app"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload(module_name: str):
    """Force a fresh import (needed after fixer writes a new file)."""
    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


# ---------------------------------------------------------------------------
# Test: apply_fixes() produces all safe files
# ---------------------------------------------------------------------------

class TestFixerProducesSafeFiles:
    @pytest.fixture(autouse=True)
    def run_fixer(self):
        """Apply all fixes once before each test in this class."""
        self.results = apply_fixes()

    def test_all_fixes_succeed(self):
        failed = [r for r in self.results if not r.success]
        assert failed == [], f"Some fixes failed: {[r.error for r in failed]}"

    def test_auth_safe_written(self):
        assert (_APP / "auth_safe.py").exists()

    def test_db_safe_written(self):
        assert (_APP / "db_safe.py").exists()

    def test_api_safe_written(self):
        assert (_APP / "api_safe.py").exists()

    def test_utils_safe_written(self):
        assert (_APP / "utils_safe.py").exists()

    def test_originals_unchanged(self):
        """Vulnerable originals must still contain the known flaws."""
        src = (_APP / "auth.py").read_text()
        assert 'ADMIN_PASSWORD = "supersecret123"' in src

        src = (_APP / "db.py").read_text()
        assert "f\"SELECT * FROM users WHERE username = '{username}'\"" in src

        src = (_APP / "api.py").read_text()
        assert "shell=True" in src

        src = (_APP / "utils.py").read_text()
        assert "hashlib.md5" in src


# ---------------------------------------------------------------------------
# Test: scanner finds NO flaws in the safe files
# ---------------------------------------------------------------------------

class TestScannerClearsAfterFix:
    @pytest.fixture(autouse=True)
    def run_fixer(self):
        apply_fixes()

    def _safe_findings(self, filename, rule_id):
        path = str(_APP / filename)
        return [f for f in scan_file(path, filename) if f.rule_id == rule_id]

    def test_no_hardcoded_secret_in_auth_safe(self):
        assert self._safe_findings("auth_safe.py", "HARDCODED_SECRET") == []

    def test_no_sql_injection_in_db_safe(self):
        assert self._safe_findings("db_safe.py", "SQL_INJECTION") == []

    def test_no_command_injection_in_api_safe(self):
        assert self._safe_findings("api_safe.py", "COMMAND_INJECTION") == []

    def test_no_path_traversal_in_utils_safe(self):
        assert self._safe_findings("utils_safe.py", "PATH_TRAVERSAL") == []

    def test_no_weak_crypto_in_utils_safe(self):
        assert self._safe_findings("utils_safe.py", "WEAK_CRYPTO") == []


# ---------------------------------------------------------------------------
# Test: test_generator writes the expected files
# ---------------------------------------------------------------------------

class TestTestGenerator:
    @pytest.fixture(autouse=True)
    def run_generator(self, tmp_path):
        self.written = generate_tests(str(tmp_path))
        self.out_dir = tmp_path

    def test_four_files_written(self):
        assert len(self.written) == 4

    def test_all_files_exist(self):
        for path in self.written:
            assert Path(path).exists(), f"Missing: {path}"

    def test_auth_test_file_present(self):
        names = {Path(p).name for p in self.written}
        assert "test_fix_auth.py" in names

    def test_db_test_file_present(self):
        names = {Path(p).name for p in self.written}
        assert "test_fix_db.py" in names

    def test_api_test_file_present(self):
        names = {Path(p).name for p in self.written}
        assert "test_fix_api.py" in names

    def test_utils_test_file_present(self):
        names = {Path(p).name for p in self.written}
        assert "test_fix_utils.py" in names

    def test_generated_files_are_valid_python(self):
        import ast
        for path in self.written:
            src = Path(path).read_text()
            try:
                ast.parse(src)
            except SyntaxError as e:
                pytest.fail(f"Syntax error in generated {path}: {e}")
