"""
tests/test_reporter.py — unit tests for sentinel.reporter and sentinel.verifier.

Verifier tests:
  - verify_scans() correctly identifies clean safe files
  - run_pytest() captures pass counts

Reporter tests:
  - write_reports() produces both files
  - JSON report has all required top-level keys
  - Markdown report contains key sections
"""

import json
import os
from pathlib import Path

import pytest

from sentinel.fixer import apply_fixes
from sentinel.test_generator import generate_tests
from sentinel.scanner import scan_directory
from sentinel.explainer import explain_all
from sentinel.verifier import verify_scans, run_pytest, verify_all
from sentinel.reporter import write_reports

_ROOT = Path(__file__).parent.parent
_APP  = _ROOT / "vulnerable_app"


# ---------------------------------------------------------------------------
# Fixtures: ensure safe files and generated tests exist before verifier runs
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def pipeline_setup():
    """Run fixer + test_generator once for the whole module."""
    apply_fixes()
    generate_tests()


# ---------------------------------------------------------------------------
# Verifier — scan verification
# ---------------------------------------------------------------------------

class TestVerifyScanResults:
    def test_returns_one_result_per_rule(self):
        results = verify_scans()
        # 5 rules total across 4 modules
        assert len(results) == 5

    def test_all_scans_pass(self):
        results = verify_scans()
        failing = [r for r in results if not r.passed]
        assert failing == [], f"Residual findings in safe files: {failing}"

    def test_hardcoded_secret_clean(self):
        results = {r.rule_id: r for r in verify_scans()}
        assert results["HARDCODED_SECRET"].passed

    def test_sql_injection_clean(self):
        results = {r.rule_id: r for r in verify_scans()}
        assert results["SQL_INJECTION"].passed

    def test_command_injection_clean(self):
        results = {r.rule_id: r for r in verify_scans()}
        assert results["COMMAND_INJECTION"].passed

    def test_path_traversal_clean(self):
        results = {r.rule_id: r for r in verify_scans()}
        assert results["PATH_TRAVERSAL"].passed

    def test_weak_crypto_clean(self):
        results = {r.rule_id: r for r in verify_scans()}
        assert results["WEAK_CRYPTO"].passed


# ---------------------------------------------------------------------------
# Verifier — pytest runner
# ---------------------------------------------------------------------------

class TestRunPytest:
    def test_returns_pytest_result(self):
        result = run_pytest([str(_ROOT / "tests" / "test_scanner.py")])
        assert result.total > 0

    def test_scanner_tests_all_pass(self):
        result = run_pytest([str(_ROOT / "tests" / "test_scanner.py")])
        assert result.passed == result.total
        assert result.failed == 0
        assert result.exit_code == 0

    def test_exit_code_zero_on_clean_suite(self):
        result = run_pytest([str(_ROOT / "tests" / "test_scanner.py")])
        assert result.all_passed


# ---------------------------------------------------------------------------
# Reporter — output files
# ---------------------------------------------------------------------------

class TestWriteReports:
    @pytest.fixture
    def report_paths(self, tmp_path):
        findings = scan_directory(str(_APP))
        explain_all(findings)
        fix_results = apply_fixes()
        # Avoid recursively launching the full suite from inside the full suite.
        verification = verify_all(test_dirs=[str(_ROOT / "tests" / "test_scanner.py")])
        return write_reports(findings, fix_results, verification, output_dir=str(tmp_path))

    def test_both_files_created(self, report_paths):
        assert Path(report_paths["json"]).exists()
        assert Path(report_paths["markdown"]).exists()

    def test_json_top_level_keys(self, report_paths):
        data = json.loads(Path(report_paths["json"]).read_text())
        for key in ("project", "timestamp", "summary", "findings"):
            assert key in data, f"Missing key: {key}"

    def test_json_summary_keys(self, report_paths):
        summary = json.loads(Path(report_paths["json"]).read_text())["summary"]
        for key in ("total_findings", "critical", "high", "fixes_applied",
                    "tests_passed", "tests_total", "overall_status"):
            assert key in summary, f"Missing summary key: {key}"

    def test_json_has_six_findings(self, report_paths):
        data = json.loads(Path(report_paths["json"]).read_text())
        assert data["summary"]["total_findings"] == 6

    def test_json_overall_status_pass(self, report_paths):
        data = json.loads(Path(report_paths["json"]).read_text())
        assert data["summary"]["overall_status"] == "PASS"

    def test_json_findings_have_required_fields(self, report_paths):
        findings = json.loads(Path(report_paths["json"]).read_text())["findings"]
        for f in findings:
            for field in ("rule_id", "owasp", "severity", "file", "line",
                          "remediation", "safe_file", "verification"):
                assert field in f, f"Finding missing field: {field}"

    def test_json_findings_all_verified(self, report_paths):
        findings = json.loads(Path(report_paths["json"]).read_text())["findings"]
        for f in findings:
            assert f["verification"]["passed"] is True, (
                f"{f['rule_id']} verification failed in report"
            )

    def test_markdown_contains_header(self, report_paths):
        md = Path(report_paths["markdown"]).read_text()
        assert "REAPER-Bob Sentinel" in md
        assert "## Summary" in md
        assert "## Findings" in md
        assert "## Verification" in md

    def test_markdown_contains_all_rule_ids(self, report_paths):
        md = Path(report_paths["markdown"]).read_text()
        for rule in ("HARDCODED_SECRET", "SQL_INJECTION", "COMMAND_INJECTION",
                     "PATH_TRAVERSAL", "WEAK_CRYPTO"):
            assert rule in md, f"Rule {rule} missing from Markdown report"

    def test_markdown_overall_pass_icon(self, report_paths):
        md = Path(report_paths["markdown"]).read_text()
        assert "✅" in md
