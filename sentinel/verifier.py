"""
sentinel/verifier.py — verification stage.

Two verification checks are run after fixes are applied:

1. Re-scan each *_safe.py file and confirm the original rule no longer fires.
2. Run the full pytest suite and capture pass/fail counts.
"""

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.scanner import scan_file
from sentinel.fixer import _FIXES, FixResult

_APP_DIR = Path(__file__).parent.parent / "vulnerable_app"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ScanVerification:
    """Result of re-scanning one safe file for a specific rule."""
    rule_id: str
    safe_file: str          # relative path, e.g. "vulnerable_app/auth_safe.py"
    residual_count: int     # findings for this rule that remain (0 = clean)

    @property
    def passed(self) -> bool:
        return self.residual_count == 0


@dataclass
class PytestResult:
    """Outcome of a pytest run."""
    passed: int
    failed: int
    errors: int
    total: int
    exit_code: int
    output: str             # captured stdout+stderr

    @property
    def all_passed(self) -> bool:
        return self.exit_code == 0


@dataclass
class VerificationReport:
    scan_results: list[ScanVerification] = field(default_factory=list)
    pytest_result: PytestResult = field(default_factory=lambda: PytestResult(0, 0, 0, 0, -1, ""))

    @property
    def all_scans_clean(self) -> bool:
        return all(r.passed for r in self.scan_results)

    @property
    def overall_passed(self) -> bool:
        return self.all_scans_clean and self.pytest_result.all_passed


# ---------------------------------------------------------------------------
# Scan verification
# ---------------------------------------------------------------------------

def verify_scans(app_dir: str | None = None) -> list[ScanVerification]:
    """Re-scan every *_safe.py file and confirm its rule(s) no longer fire."""
    base = Path(app_dir) if app_dir else _APP_DIR
    results: list[ScanVerification] = []

    for entry in _FIXES:
        safe_path = base / entry.safe_module
        rel = str(safe_path.relative_to(safe_path.parent.parent))
        if not safe_path.exists():
            for rule_id in entry.rule_ids:
                results.append(ScanVerification(rule_id=rule_id, safe_file=rel, residual_count=-1))
            continue

        all_findings = scan_file(str(safe_path), rel)
        for rule_id in entry.rule_ids:
            count = sum(1 for f in all_findings if f.rule_id == rule_id)
            results.append(ScanVerification(rule_id=rule_id, safe_file=rel, residual_count=count))

    return results


# ---------------------------------------------------------------------------
# Pytest runner
# ---------------------------------------------------------------------------

def run_pytest(test_dirs: list[str] | None = None) -> PytestResult:
    """Run pytest programmatically and return structured results."""
    project_root = Path(__file__).parent.parent
    dirs = test_dirs or [str(project_root / "tests")]

    cmd = [sys.executable, "-m", "pytest"] + dirs + ["-v", "--tb=short", "-q"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    output = proc.stdout + proc.stderr

    # Parse summary line, e.g. "67 passed in 0.28s" or "65 passed, 2 failed in 1.2s"
    passed = failed = errors = 0
    for line in output.splitlines():
        line = line.strip()
        if " passed" in line or " failed" in line or " error" in line:
            import re
            passed  = int(m.group(1)) if (m := re.search(r"(\d+) passed",  line)) else passed
            failed  = int(m.group(1)) if (m := re.search(r"(\d+) failed",  line)) else failed
            errors  = int(m.group(1)) if (m := re.search(r"(\d+) error",   line)) else errors

    total = passed + failed + errors
    return PytestResult(
        passed=passed,
        failed=failed,
        errors=errors,
        total=total,
        exit_code=proc.returncode,
        output=output,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_all(app_dir: str | None = None, test_dirs: list[str] | None = None) -> VerificationReport:
    """Run both verification checks and return a combined report."""
    report = VerificationReport()
    report.scan_results = verify_scans(app_dir)
    report.pytest_result = run_pytest(test_dirs)
    return report
