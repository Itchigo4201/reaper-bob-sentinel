# Hackathon Submission Kit

## Project

**REAPER-Bob Sentinel**

Security and debugging assistant built with IBM Bob.

## 100-word description

REAPER-Bob Sentinel is a security and debugging assistant built with IBM Bob. It demonstrates a complete remediation workflow: detect, explain, fix, test-generate, verify, and report. Sentinel scans an intentionally vulnerable Python application for command injection, SQL injection, hardcoded secrets, path traversal, and weak password hashing. It explains each finding, writes safe replacement modules, generates regression tests, re-scans the fixes, runs the test suite, and produces JSON and Markdown reports. The final demo resolves six findings, including two critical issues, and finishes with 87 passing tests. The project is local, deterministic, transparent, and designed to show Bob-driven secure development in practice.

## One-line pitch

REAPER-Bob Sentinel turns security findings into verified fixes by carrying code from detection all the way through explanation, remediation, regression testing, verification, and reporting.

## Problem

Security tools often stop at detection. Developers still have to understand the issue, patch it safely, prove the patch works, and document the result.

## Solution

Sentinel demonstrates an agentic remediation loop where IBM Bob helps move from a vulnerable codebase to tested, re-scanned, documented safe replacements in one reproducible workflow.
## Technical highlights

- Python 3.12
- AST-based static analysis
- OWASP-mapped findings
- Safe replacement modules that preserve vulnerable originals
- Generated regression tests
- Re-scan verification
- Programmatic pytest verification
- JSON + Markdown reports
- scrypt password hashing with random salts
- Fully local demo

## Demo command

```bash
.venv/bin/python demo.py
```

Expected final line:

```text
✓ ALL CLEAR · 6/6 findings fixed · 87/87 tests passing
```

## Three-minute demo script

**0:00–0:20 — Problem**
“Most security tools tell you what is wrong and then stop. REAPER-Bob Sentinel demonstrates what happens when IBM Bob helps carry the workflow through the fix, tests, verification, and report.”

**0:20–0:45 — Architecture**
Show the repository tree: `sentinel/`, `vulnerable_app/`, `tests/`, `reports/`, and `AGENTS.md`. Mention that `/init` gave Bob persistent project context.
**0:45–1:30 — Detection**
Run `.venv/bin/python demo.py`. Point out the six findings: command injection, SQL injection, two hardcoded secrets, path traversal, and weak password hashing. Highlight the OWASP mappings and severity.

**1:30–2:10 — Fix + tests**
Show that Sentinel writes `*_safe.py` files while preserving the originals. Point out the generated regression tests and the scrypt password-hashing fix with random salt and verification.

**2:10–2:40 — Verification**
Show the safe-file re-scan: all five rules are clean. Show `87/87 tests passed`.

**2:40–3:00 — Report + close**
Open `reports/sentinel_report.md`. Show the finding, remediation, safe file, verification result, and final PASS status.

Close with:
“Sentinel’s goal is simple: don’t stop at finding the bug. Explain it, fix it, prove it, and leave an auditable report.”

## Suggested screenshots

1. Final terminal `ALL CLEAR` output.
2. Vulnerable file beside its `*_safe.py` replacement.
3. Generated Markdown security report.
4. IBM Bob chat/task history showing the agentic build workflow.
