"""
sentinel/reporter.py — produces the final security report.

Outputs:
  reports/sentinel_report.json   — machine-readable structured report
  reports/sentinel_report.md     — human-readable Markdown report

The report combines:
  - project metadata + scan timestamp
  - original findings (rule, OWASP, severity, file, line, explanation)
  - per-finding remediation applied and safe replacement file
  - per-rule scan verification result (clean / residual findings)
  - overall pytest result (passed/failed/total)
  - final pass/fail status
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from sentinel.models import Finding
from sentinel.fixer import _FIXES, FixResult
from sentinel.verifier import VerificationReport

_REPORTS_DIR = Path(__file__).parent.parent / "reports"
_PROJECT_NAME = "REAPER-Bob Sentinel"

_SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🟢 LOW",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fix_meta_for_finding(finding: Finding) -> dict:
    """Return the fix entry metadata relevant to a given finding."""
    rule_overrides = {
        "PATH_TRAVERSAL": "Resolve and validate path containment within the allowed base directory",
        "WEAK_CRYPTO": "Replace MD5 password hashing with salted scrypt and verify_password()",
    }
    for entry in _FIXES:
        if finding.rule_id in entry.rule_ids:
            return {
                "description": rule_overrides.get(finding.rule_id, entry.description),
                "safe_file": f"vulnerable_app/{entry.safe_module}",
            }
    return {"description": "No fix available", "safe_file": ""}


def _scan_result_for_finding(finding: Finding, report: VerificationReport) -> dict:
    """Return the scan verification result for a given finding's rule."""
    for sr in report.scan_results:
        if sr.rule_id == finding.rule_id:
            return {
                "rule_id": sr.rule_id,
                "safe_file": sr.safe_file,
                "residual_findings": sr.residual_count,
                "passed": sr.passed,
            }
    return {"rule_id": finding.rule_id, "safe_file": "", "residual_findings": -1, "passed": False}


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _build_report_dict(
    findings: list[Finding],
    fix_results: list[FixResult],
    verification: VerificationReport,
    timestamp: str,
) -> dict:
    pr = verification.pytest_result

    finding_records = []
    for f in findings:
        fix_meta  = _fix_meta_for_finding(f)
        scan_res  = _scan_result_for_finding(f, verification)
        finding_records.append({
            "rule_id":          f.rule_id,
            "owasp":            f.owasp,
            "severity":         f.severity,
            "file":             f.file,
            "line":             f.line,
            "symbol":           f.symbol,
            "message":          f.message,
            "snippet":          f.snippet.strip(),
            "explanation":      f.explanation,
            "remediation":      fix_meta["description"],
            "safe_file":        fix_meta["safe_file"],
            "verification":     scan_res,
        })

    return {
        "project":    _PROJECT_NAME,
        "timestamp":  timestamp,
        "summary": {
            "total_findings":   len(findings),
            "critical":         sum(1 for f in findings if f.severity == "CRITICAL"),
            "high":             sum(1 for f in findings if f.severity == "HIGH"),
            "medium":           sum(1 for f in findings if f.severity == "MEDIUM"),
            "low":              sum(1 for f in findings if f.severity == "LOW"),
            "fixes_applied":    sum(1 for r in fix_results if r.success),
            "scans_clean":      sum(1 for sr in verification.scan_results if sr.passed),
            "scans_total":      len(verification.scan_results),
            "tests_passed":     pr.passed,
            "tests_failed":     pr.failed,
            "tests_total":      pr.total,
            "overall_status":   "PASS" if verification.overall_passed else "FAIL",
        },
        "findings": finding_records,
    }


def write_json(
    findings: list[Finding],
    fix_results: list[FixResult],
    verification: VerificationReport,
    timestamp: str,
    output_dir: str | None = None,
) -> str:
    out = Path(output_dir) if output_dir else _REPORTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / "sentinel_report.json"
    data = _build_report_dict(findings, fix_results, verification, timestamp)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
_TICK = "✅"
_CROSS = "❌"


def write_markdown(
    findings: list[Finding],
    fix_results: list[FixResult],
    verification: VerificationReport,
    timestamp: str,
    output_dir: str | None = None,
) -> str:
    out = Path(output_dir) if output_dir else _REPORTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / "sentinel_report.md"

    pr = verification.pytest_result
    overall = _TICK if verification.overall_passed else _CROSS
    lines: list[str] = []

    # --- Header ---
    lines += [
        f"# {_PROJECT_NAME} — Security Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Overall status:** {overall} {'PASS' if verification.overall_passed else 'FAIL'}",
        "",
    ]

    # --- Executive summary ---
    lines += [
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Findings detected | {len(findings)} |",
        f"| CRITICAL | {sum(1 for f in findings if f.severity == 'CRITICAL')} |",
        f"| HIGH | {sum(1 for f in findings if f.severity == 'HIGH')} |",
        f"| Fixes applied | {sum(1 for r in fix_results if r.success)} |",
        f"| Scan verifications passed | {sum(1 for sr in verification.scan_results if sr.passed)} / {len(verification.scan_results)} |",
        f"| Tests passed | {pr.passed} / {pr.total} |",
        "",
    ]

    # --- Findings ---
    lines += ["## Findings", ""]

    for i, f in enumerate(findings, 1):
        icon = _SEVERITY_ICON.get(f.severity, "⚪")
        fix_meta = _fix_meta_for_finding(f)
        scan_res = _scan_result_for_finding(f, verification)
        verify_icon = _TICK if scan_res["passed"] else _CROSS

        lines += [
            f"### {i}. {icon} `{f.rule_id}` — {f.owasp}",
            "",
            f"| Field | Detail |",
            f"|-------|--------|",
            f"| **Severity** | {f.severity} |",
            f"| **File** | `{f.file}` line {f.line} |",
            f"| **Symbol** | `{f.symbol}` |",
            f"| **Message** | {f.message} |",
            f"| **Remediation** | {fix_meta['description']} |",
            f"| **Safe file** | `{fix_meta['safe_file']}` |",
            f"| **Verification** | {verify_icon} `{f.rule_id}` no longer detected in safe file |",
            "",
        ]

        if f.snippet:
            lines += [
                "**Vulnerable snippet:**",
                "```python",
                f.snippet.strip(),
                "```",
                "",
            ]

        if f.explanation:
            # Strip the leading "## Title" line — already shown above
            body = "\n".join(f.explanation.splitlines()[2:]).strip()
            if body:
                lines += [
                    "<details>",
                    "<summary>Root cause &amp; remediation detail</summary>",
                    "",
                    body,
                    "",
                    "</details>",
                    "",
                ]

    # --- Verification ---
    lines += [
        "## Verification",
        "",
        "### Static re-scan (safe files)",
        "",
        "| Rule | Safe file | Result |",
        "|------|-----------|--------|",
    ]
    for sr in verification.scan_results:
        icon = _TICK if sr.passed else _CROSS
        lines.append(f"| `{sr.rule_id}` | `{sr.safe_file}` | {icon} {'Clean' if sr.passed else f'{sr.residual_count} finding(s) remain'} |")

    lines += [
        "",
        "### Test suite",
        "",
        f"| Result | Count |",
        f"|--------|-------|",
        f"| Passed | {pr.passed} |",
        f"| Failed | {pr.failed} |",
        f"| Total  | {pr.total} |",
        "",
        f"**Exit code:** `{pr.exit_code}` — {'All tests passed.' if pr.all_passed else 'Some tests failed.'}",
        "",
    ]

    # --- Footer ---
    lines += [
        "---",
        "",
        f"*Generated by {_PROJECT_NAME} · IBM Bob Hackathon 2026*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_reports(
    findings: list[Finding],
    fix_results: list[FixResult],
    verification: VerificationReport,
    output_dir: str | None = None,
) -> dict[str, str]:
    """Write both JSON and Markdown reports.  Returns dict of {format: path}."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "json": write_json(findings, fix_results, verification, timestamp, output_dir),
        "markdown": write_markdown(findings, fix_results, verification, timestamp, output_dir),
    }
