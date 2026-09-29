"""
demo.py — REAPER-Bob Sentinel  (Milestones 1 + 2)

Pipeline:  detect → explain → fix → test-generate

Run:  .venv/bin/python demo.py
"""

import os
import textwrap
from collections import Counter
from pathlib import Path

from sentinel.scanner import scan_directory
from sentinel.explainer import explain_all
from sentinel.fixer import apply_fixes
from sentinel.test_generator import generate_tests

_SEP  = "─" * 72
_SEP2 = "╌" * 72
_APP_DIR = str(Path(__file__).parent / "vulnerable_app")

_SEVERITY_COLOUR = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[0;31m",
    "MEDIUM":   "\033[0;33m",
    "LOW":      "\033[0;32m",
}
_GREEN  = "\033[0;32m"
_CYAN   = "\033[0;36m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Stage 1 — detect → explain
# ---------------------------------------------------------------------------

def stage_detect_explain() -> list:
    print(f"\n{_c(_BOLD, 'STAGE 1 — DETECT  →  EXPLAIN')}")
    print(_SEP)
    print(f"  Target : {_APP_DIR}")
    print(_SEP)

    findings = scan_directory(_APP_DIR)
    explain_all(findings)

    for i, f in enumerate(findings, 1):
        tag = _c(_SEVERITY_COLOUR.get(f.severity, ""), f"[{f.severity}]")
        print(f"\nFinding {i:02d}/{len(findings):02d}  {tag}")
        print(f"  Rule    : {f.rule_id}")
        print(f"  OWASP   : {f.owasp}")
        print(f"  File    : {f.file}  (line {f.line})")
        print(f"  Snippet : {f.snippet.strip()}")
        if f.explanation:
            title_line = f.explanation.split("\n")[0]   # ## Title
            print(f"  Explain : {title_line.lstrip('# ')}")

    counts = Counter(f.severity for f in findings)
    parts  = [_c(_SEVERITY_COLOUR[s], f"{counts[s]} {s}")
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    print(f"\n{_SEP}")
    print(f"  Detected {len(findings)} findings  |  {', '.join(parts)}")
    print(_SEP)
    return findings


# ---------------------------------------------------------------------------
# Stage 2 — fix
# ---------------------------------------------------------------------------

def stage_fix(findings: list) -> list:
    print(f"\n{_c(_BOLD, 'STAGE 2 — FIX')}")
    print(_SEP)

    results = apply_fixes()

    # Build a lookup: rule_id → fix description
    from sentinel.fixer import _FIXES
    rule_to_desc = {}
    for entry in _FIXES:
        for rid in entry.rule_ids:
            rule_to_desc[rid] = (entry.description, entry.safe_module)

    for f in findings:
        desc, safe_mod = rule_to_desc.get(f.rule_id, ("(no fix)", ""))
        status = _c(_GREEN, "✓ FIXED")
        print(f"  {status}  {f.rule_id:25s}  →  {safe_mod}")
        print(f"            {desc}")

    ok  = sum(1 for r in results if r.success)
    bad = sum(1 for r in results if not r.success)
    print(_SEP2)
    print(f"  {ok} fix module(s) written"
          + (f"  |  {_c(_SEVERITY_COLOUR['CRITICAL'], str(bad) + ' failed')}" if bad else ""))
    print(_SEP)
    return results


# ---------------------------------------------------------------------------
# Stage 3 — test-generate
# ---------------------------------------------------------------------------

def stage_test_generate() -> list:
    print(f"\n{_c(_BOLD, 'STAGE 3 — TEST-GENERATE')}")
    print(_SEP)

    written = generate_tests()

    for path in written:
        rel = os.path.relpath(path, start=str(Path(__file__).parent))
        print(f"  {_c(_CYAN, 'generated')}  {rel}")

    print(_SEP2)
    print(f"  {len(written)} regression test file(s) written to tests/generated/")
    print(_SEP)
    return written


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print(_SEP)
    print(_c(_BOLD, "  REAPER-Bob Sentinel  |  Milestones 1 + 2"))
    print(_SEP)

    findings       = stage_detect_explain()
    _fix_results   = stage_fix(findings)
    _test_files    = stage_test_generate()

    print(f"\n{_c(_BOLD, 'PIPELINE COMPLETE')}")
    print(_SEP)
    print("  Next step: run the generated regression tests to verify fixes.")
    print("  Command  : .venv/bin/python -m pytest tests/generated/ -v")
    print(_SEP)


if __name__ == "__main__":
    main()
