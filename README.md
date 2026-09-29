# REAPER-Bob Sentinel

**IBM Bob Hackathon 2026 — Security & Debugging Assistant**

REAPER-Bob Sentinel demonstrates a complete secure-development loop:

`detect → explain → fix → test-generate → verify → report`

The project uses IBM Bob to help inspect, reason about, repair, test, and verify an intentionally vulnerable Python application. The demo stays local and deterministic so every result is reproducible.

## Demo result

- 6 security findings detected
- 2 CRITICAL and 4 HIGH findings
- 5 security rule categories
- 4 safe replacement modules generated
- 4 regression-test files generated
- 5/5 safe-file re-scans clean
- 87/87 tests passing
- JSON and Markdown security reports generated

## Findings covered

| Rule | Severity | OWASP mapping |
|---|---|---|
| Command Injection | CRITICAL | A03:2021 Injection |
| SQL Injection | CRITICAL | A03:2021 Injection |
| Hardcoded Secrets | HIGH | A02:2021 Cryptographic Failures |
| Path Traversal | HIGH | A01:2021 Broken Access Control |
| Weak Password Hashing | HIGH | A02:2021 Cryptographic Failures |
## How it works

1. **Detect** — AST-based rules scan the vulnerable sample app.
2. **Explain** — each finding receives a root-cause explanation and remediation guidance.
3. **Fix** — safe sibling modules are generated without overwriting the vulnerable originals.
4. **Test-generate** — regression tests are produced for the remediations.
5. **Verify** — safe files are re-scanned and the pytest suite is executed.
6. **Report** — machine-readable JSON and human-readable Markdown reports are written.

## Quick start

```bash
git clone https://github.com/Itchigo4201/reaper-bob-sentinel.git
cd reaper-bob-sentinel

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python demo.py
```

Run the full test suite:

```bash
.venv/bin/python -m pytest -q
```

Expected result:

```text
87 passed
✓ ALL CLEAR · 6/6 findings fixed · 87/87 tests passing
```
## Project structure

```text
reaper-bob-sentinel/
├── demo.py
├── sentinel/
│   ├── scanner.py
│   ├── explainer.py
│   ├── fixer.py
│   ├── test_generator.py
│   ├── verifier.py
│   └── reporter.py
├── vulnerable_app/
│   ├── *_safe.py
│   └── intentionally vulnerable originals
├── tests/
│   └── generated/
├── reports/
│   ├── sentinel_report.json
│   └── sentinel_report.md
└── AGENTS.md
```

## IBM Bob usage

IBM Bob was used throughout the project for project initialization with `/init`, architecture planning, multi-file implementation, debugging, security reasoning, regression-test generation, iterative verification, and report/demo refinement.

The repository keeps `AGENTS.md` as persistent project context for Bob.

## Reports

After running `demo.py`, review:

- `reports/sentinel_report.json`
- `reports/sentinel_report.md`

## Scope and limitations

This is a hackathon proof of concept, not a replacement for production SAST tooling. Detection is intentionally focused on a small set of call-site patterns in Python AST. The vulnerable examples exist only to make the full remediation workflow reproducible and easy to demonstrate.

## Status

**Hackathon MVP complete — 87/87 tests passing.**
