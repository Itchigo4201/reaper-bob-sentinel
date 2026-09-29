# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project

**REAPER-Bob Sentinel** — IBM Bob Hackathon 2026 security and debugging assistant.
Pipeline: `detect → explain → fix → test → verify → report`
Stack: Python 3.12, pytest, stdlib `ast` only (no third-party analysis libs).

## Commands

```bash
# Create venv (first time)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Run full demo (detect → explain → fix → test-generate → verify → report)
.venv/bin/python demo.py

# Run all tests (scanner + fixer + generated regressions + verifier + reporter)
.venv/bin/python -m pytest tests/ -v

# Run a single test class
.venv/bin/python -m pytest tests/test_scanner.py::TestSqlInjection -v

# Run a single test
.venv/bin/python -m pytest tests/test_scanner.py::TestSqlInjection::test_detects_fstring_in_execute -v

# Run only generated regression tests
.venv/bin/python -m pytest tests/generated/ -v
```

## Architecture

```
demo.py
  └─ sentinel/scanner.py       scan_directory()  → List[Finding]
  └─ sentinel/explainer.py     explain_all()     → populates Finding.explanation
  └─ sentinel/fixer.py         apply_fixes()     → writes vulnerable_app/*_safe.py
  └─ sentinel/test_generator.py generate_tests() → writes tests/generated/test_fix_*.py
  └─ sentinel/verifier.py      verify_all()       → re-scan + pytest verification
  └─ sentinel/reporter.py      write_reports()    → JSON + Markdown reports
```

- `sentinel/models.py` — `Finding` dataclass; shared by all stages.
- `sentinel/scanner.py` — pure AST rules, no taint-tracking.  Patterns must be
  detectable at the call site (f-string/`shell=True` must appear *directly* in
  the call, not via a pre-assigned variable).  `PATH_TRAVERSAL` rule skips
  `os.path.join()` calls that are immediately wrapped in `os.path.realpath()`.
- `sentinel/fixer.py` — writes `*_safe.py` siblings; originals are never modified.
- `sentinel/test_generator.py` — templates use `chr(10)` instead of `"\n"` for
  join operations inside triple-quoted strings (avoids literal-newline injection).
- Rules: `HARDCODED_SECRET`, `SQL_INJECTION`, `COMMAND_INJECTION`,
  `PATH_TRAVERSAL`, `WEAK_CRYPTO`.

## Non-obvious Constraints

- **AST rules are call-site only** — if a flaw is assigned to a variable before
  being passed to a sink, the scanner will miss it. Keep `vulnerable_app/` flaws
  inline at the call.
- `scan_directory()` resolves paths relative to `target.parent`, so
  `Finding.file` always starts with the directory name (e.g. `vulnerable_app/db.py`).
- Severity sort order is hardcoded: CRITICAL → HIGH → MEDIUM → LOW.
- Generated test files in `tests/generated/` are overwritten on every `demo.py`
  run — do not hand-edit them; edit the templates in `sentinel/test_generator.py`.
- Template strings that check for `shell=True` absence must exclude docstring
  lines (use `chr(10).join(...)` not `"\n".join(...)` inside triple-quoted templates).

## Milestones

- **M1** ✅ `detect → explain` — scanner + explainer + 20 tests
- **M2** ✅ `fix → test-generate` — fixer + test_generator + 40 tests
- **M3** ✅ `verify → report` — verifier + reporter + final demo; 87 tests passing
