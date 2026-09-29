"""
tests/test_scanner.py — unit tests for sentinel.scanner.

Each test scans one specific vulnerable_app module and asserts that the
expected rule fires at the expected line.  Tests are intentionally narrow
so a single pytest -k filter can target them individually.
"""

import pytest

from sentinel.scanner import scan_file
from sentinel.models import Finding

import os

# Resolve paths relative to the project root regardless of cwd
_HERE = os.path.dirname(__file__)
_ROOT = os.path.dirname(_HERE)
_APP = os.path.join(_ROOT, "vulnerable_app")


def _findings_by_rule(filename: str, rule_id: str) -> list[Finding]:
    path = os.path.join(_APP, filename)
    all_f = scan_file(path, f"vulnerable_app/{filename}")
    return [f for f in all_f if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# HARDCODED_SECRET — auth.py
# ---------------------------------------------------------------------------

class TestHardcodedSecret:
    def test_detects_admin_password(self):
        findings = _findings_by_rule("auth.py", "HARDCODED_SECRET")
        names = {f.symbol for f in findings}
        assert "ADMIN_PASSWORD" in names

    def test_detects_secret_key(self):
        findings = _findings_by_rule("auth.py", "HARDCODED_SECRET")
        names = {f.symbol for f in findings}
        assert "SECRET_KEY" in names

    def test_owasp_category(self):
        findings = _findings_by_rule("auth.py", "HARDCODED_SECRET")
        for f in findings:
            assert f.owasp == "A02:2021 Cryptographic Failures"

    def test_severity_is_high(self):
        findings = _findings_by_rule("auth.py", "HARDCODED_SECRET")
        for f in findings:
            assert f.severity == "HIGH"

    def test_snippet_is_populated(self):
        findings = _findings_by_rule("auth.py", "HARDCODED_SECRET")
        for f in findings:
            assert f.snippet.strip() != ""


# ---------------------------------------------------------------------------
# SQL_INJECTION — db.py
# ---------------------------------------------------------------------------

class TestSqlInjection:
    def test_detects_fstring_in_execute(self):
        findings = _findings_by_rule("db.py", "SQL_INJECTION")
        assert len(findings) >= 1

    def test_owasp_category(self):
        findings = _findings_by_rule("db.py", "SQL_INJECTION")
        for f in findings:
            assert f.owasp == "A03:2021 Injection"

    def test_severity_is_critical(self):
        findings = _findings_by_rule("db.py", "SQL_INJECTION")
        for f in findings:
            assert f.severity == "CRITICAL"

    def test_snippet_contains_fstring(self):
        findings = _findings_by_rule("db.py", "SQL_INJECTION")
        assert any("f'" in f.snippet or 'f"' in f.snippet for f in findings)


# ---------------------------------------------------------------------------
# COMMAND_INJECTION — api.py
# ---------------------------------------------------------------------------

class TestCommandInjection:
    def test_detects_shell_true(self):
        findings = _findings_by_rule("api.py", "COMMAND_INJECTION")
        assert len(findings) >= 1

    def test_owasp_category(self):
        findings = _findings_by_rule("api.py", "COMMAND_INJECTION")
        for f in findings:
            assert f.owasp == "A03:2021 Injection"

    def test_severity_is_critical(self):
        findings = _findings_by_rule("api.py", "COMMAND_INJECTION")
        for f in findings:
            assert f.severity == "CRITICAL"

    def test_symbol_identifies_subprocess(self):
        findings = _findings_by_rule("api.py", "COMMAND_INJECTION")
        assert any("subprocess" in f.symbol for f in findings)


# ---------------------------------------------------------------------------
# PATH_TRAVERSAL — utils.py
# ---------------------------------------------------------------------------

class TestPathTraversal:
    def test_detects_unsanitised_join(self):
        findings = _findings_by_rule("utils.py", "PATH_TRAVERSAL")
        assert len(findings) >= 1

    def test_owasp_category(self):
        findings = _findings_by_rule("utils.py", "PATH_TRAVERSAL")
        for f in findings:
            assert f.owasp == "A01:2021 Broken Access Control"

    def test_severity_is_high(self):
        findings = _findings_by_rule("utils.py", "PATH_TRAVERSAL")
        for f in findings:
            assert f.severity == "HIGH"


# ---------------------------------------------------------------------------
# WEAK_CRYPTO — utils.py
# ---------------------------------------------------------------------------

class TestWeakCrypto:
    def test_detects_md5(self):
        findings = _findings_by_rule("utils.py", "WEAK_CRYPTO")
        assert any("md5" in f.symbol for f in findings)

    def test_owasp_category(self):
        findings = _findings_by_rule("utils.py", "WEAK_CRYPTO")
        for f in findings:
            assert f.owasp == "A02:2021 Cryptographic Failures"

    def test_severity_is_high(self):
        findings = _findings_by_rule("utils.py", "WEAK_CRYPTO")
        for f in findings:
            assert f.severity == "HIGH"


# ---------------------------------------------------------------------------
# No false positives in clean files
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_models_has_no_findings(self):
        """sentinel/models.py is clean — scanner should report nothing."""
        path = os.path.join(_ROOT, "sentinel", "models.py")
        findings = scan_file(path, "sentinel/models.py")
        assert findings == []
