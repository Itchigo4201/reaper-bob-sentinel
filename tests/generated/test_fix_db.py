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
