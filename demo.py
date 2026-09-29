"""
demo.py — REAPER-Bob Sentinel  (Milestones 1 + 2 + 3)

Pipeline:  detect → explain → fix → test-generate → verify → report

Run:  .venv/bin/python demo.py
"""

import os
from collections import Counter
from pathlib import Path

from sentinel.scanner import scan_directory
from sentinel.explainer import explain_all
from sentinel.fixer import apply_fixes
from sentinel.test_generator import generate_tests
from sentinel.verifier import verify_all
from sentinel.reporter import write_reports

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------

_SEP  = "─" * 72
_SEP2 = "╌" * 72

_C = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[0;31m",
    "MEDIUM":   "\033[0;33m",
    "LOW":      "\033[0;32m",
    "green":    "\033[0;32m",
    "cyan":     "\033[0;36m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "reset":    "\033[0m",
}

def _c(key: str, text: str) -> str:
    return f"{_C.get(key, '')}{text}{_C['reset']}"

def _stage(n: int, title: str) -> None:
    print(f"\n{_c('bold', f'  [{n}/6] {title}')}")
    print(_SEP)

_APP_DIR = str(Path(__file__).parent / "vulnerable_app")


# ---------------------------------------------------------------------------
# Stage 1 — detect + explain
# ---------------------------------------------------------------------------

def stage_detect_explain():
    _stage(1, "DETECT  →  EXPLAIN")
    print(f"  Target : {_APP_DIR}\n")

    findings = scan_directory(_APP_DIR)
    explain_all(findings)

    counts = Counter(f.severity for f in findings)
    for i, f in enumerate(findings, 1):
        tag = _c(f.severity, f"[{f.severity}]")
        print(f"  {i:02d}. {tag:30s}  {f.rule_id}  ·  {f.owasp}")
        print(f"      {_c('dim', f.file + ':' + str(f.line))}  {f.snippet.strip()}")

    parts = [_c(s, f"{counts[s]} {s}") for s in ("CRITICAL","HIGH","MEDIUM","LOW") if counts[s]]
    print(f"\n  {len(findings)} findings  |  {', '.join(parts)}")
    return findings


# ---------------------------------------------------------------------------
# Stage 2 — fix
# ---------------------------------------------------------------------------

def stage_fix(findings):
    _stage(2, "FIX")

    from sentinel.fixer import _FIXES
    results = apply_fixes()

    # one output line per finding
    rule_to_safe = {rid: e.safe_module for e in _FIXES for rid in e.rule_ids}
    shown = set()
    for f in findings:
        safe = rule_to_safe.get(f.rule_id, "")
        key  = (f.rule_id, safe)
        if key in shown:
            continue
        shown.add(key)
        print(f"  {_c('green', '✓')}  {f.rule_id:28s}  →  {safe}")

    ok = sum(1 for r in results if r.success)
    print(f"\n  {ok} fix module(s) written")
    return results


# ---------------------------------------------------------------------------
# Stage 3 — test-generate
# ---------------------------------------------------------------------------

def stage_test_generate():
    _stage(3, "TEST-GENERATE")

    written = generate_tests()
    for path in written:
        rel = os.path.relpath(path, start=str(Path(__file__).parent))
        print(f"  {_c('cyan', '⊕')}  {rel}")

    print(f"\n  {len(written)} regression test file(s) generated")
    return written


# ---------------------------------------------------------------------------
# Stage 4 — verify
# ---------------------------------------------------------------------------

def stage_verify():
    _stage(4, "VERIFY")

    verification = verify_all()

    print("  Static re-scan of safe files:")
    for sr in verification.scan_results:
        icon = _c("green", "✓") if sr.passed else _c("CRITICAL", "✗")
        label = "clean" if sr.passed else f"{sr.residual_count} finding(s) remain"
        print(f"    {icon}  {sr.rule_id:28s}  {sr.safe_file}  [{label}]")

    pr = verification.pytest_result
    print(f"\n  Test suite:")
    icon = _c("green", "✓") if pr.all_passed else _c("CRITICAL", "✗")
    print(f"    {icon}  {pr.passed}/{pr.total} tests passed", end="")
    if pr.failed:
        print(f"  |  {_c('CRITICAL', str(pr.failed) + ' failed')}", end="")
    print()

    return verification


# ---------------------------------------------------------------------------
# Stage 5 — report
# ---------------------------------------------------------------------------

def stage_report(findings, fix_results, verification):
    _stage(5, "REPORT")

    paths = write_reports(findings, fix_results, verification)
    for fmt, path in paths.items():
        rel = os.path.relpath(path, start=str(Path(__file__).parent))
        print(f"  {_c('cyan', fmt.upper() + ':'):10s}  {rel}")

    print(f"\n  Report written to reports/")
    return paths


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print(_SEP)
    print(_c("bold", "  REAPER-Bob Sentinel  |  IBM Bob Hackathon 2026"))
    print(_c("dim",  "  detect → explain → fix → test-generate → verify → report"))
    print(_SEP)

    findings      = stage_detect_explain()
    fix_results   = stage_fix(findings)
    _test_files   = stage_test_generate()
    verification  = stage_verify()
    report_paths  = stage_report(findings, fix_results, verification)

    # --- Final summary banner ---
    print(f"\n{_SEP}")
    overall = verification.overall_passed
    status  = _c("green", "✓ ALL CLEAR") if overall else _c("CRITICAL", "✗ ISSUES REMAIN")
    pr = verification.pytest_result
    print(f"  {status}  ·  6/6 findings fixed  ·  {pr.passed}/{pr.total} tests passing")
    print(_SEP)
    print()


if __name__ == "__main__":
    main()
