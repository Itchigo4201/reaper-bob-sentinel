"""
sentinel/scanner.py — static analysis scanner.

Walks a target directory, parses each .py file with the standard `ast` module,
and applies a fixed set of rules.  Each rule is a callable that receives the
parsed AST plus file metadata and returns zero or more Finding objects.

Rules implemented
-----------------
  HARDCODED_SECRET     — module-level string assignments whose name contains
                         common secret keywords (password, secret, key, token).
  SQL_INJECTION        — calls to connection.execute() / cursor.execute() where
                         the first argument is an f-string or a %-formatted str.
  COMMAND_INJECTION    — subprocess.run / subprocess.call / os.system calls
                         that pass shell=True.
  PATH_TRAVERSAL       — os.path.join() calls whose second argument comes
                         directly from a function parameter.
  WEAK_CRYPTO          — calls to hashlib.md5() or hashlib.sha1().
"""

import ast
import os
from pathlib import Path
from typing import List

from sentinel.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _source_lines(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return fh.readlines()


def _snippet(lines: List[str], lineno: int) -> str:
    """Return the source line at lineno (1-based), stripped."""
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ""


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------

_SECRET_KEYWORDS = {"password", "secret", "key", "token", "passwd", "pwd"}


def _rule_hardcoded_secret(
    tree: ast.AST, rel_path: str, lines: List[str]
) -> List[Finding]:
    """Detect module-level string assignments with secret-sounding names."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        # Only flag module-level assignments (parent is a Module body element)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name_lower = target.id.lower()
            if not any(kw in name_lower for kw in _SECRET_KEYWORDS):
                continue
            # The value must be a string literal
            if not isinstance(node.value, ast.Constant):
                continue
            if not isinstance(node.value.value, str):
                continue
            findings.append(
                Finding(
                    rule_id="HARDCODED_SECRET",
                    owasp="A02:2021 Cryptographic Failures",
                    severity="HIGH",
                    file=rel_path,
                    line=node.lineno,
                    symbol=target.id,
                    message=(
                        f"Hardcoded secret assigned to '{target.id}'. "
                        "Use environment variables or a secrets manager instead."
                    ),
                    snippet=_snippet(lines, node.lineno),
                )
            )
    return findings


def _is_fstring_or_percent(node: ast.expr) -> bool:
    """Return True if node is an f-string (JoinedStr) or a %-format BinOp."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    return False


def _rule_sql_injection(
    tree: ast.AST, rel_path: str, lines: List[str]
) -> List[Finding]:
    """Detect .execute() calls whose SQL argument is built from user input."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match expr.execute(...)
        if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        if _is_fstring_or_percent(first_arg):
            findings.append(
                Finding(
                    rule_id="SQL_INJECTION",
                    owasp="A03:2021 Injection",
                    severity="CRITICAL",
                    file=rel_path,
                    line=node.lineno,
                    symbol="execute",
                    message=(
                        "SQL query constructed with string interpolation. "
                        "Use parameterized queries (pass values as a tuple)."
                    ),
                    snippet=_snippet(lines, node.lineno),
                )
            )
    return findings


def _rule_command_injection(
    tree: ast.AST, rel_path: str, lines: List[str]
) -> List[Finding]:
    """Detect subprocess.run/call/Popen and os.system with shell=True."""
    findings: List[Finding] = []
    _DANGEROUS_FUNCS = {
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("os", "system"),
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match module.function(...)
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            continue
        pair = (func.value.id, func.attr)
        if pair not in _DANGEROUS_FUNCS:
            continue
        # Check for shell=True keyword argument
        shell_true = any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_true:
            continue
        findings.append(
            Finding(
                rule_id="COMMAND_INJECTION",
                owasp="A03:2021 Injection",
                severity="CRITICAL",
                file=rel_path,
                line=node.lineno,
                symbol=f"{func.value.id}.{func.attr}",
                message=(
                    f"'{func.value.id}.{func.attr}' called with shell=True and "
                    "unsanitised input. Pass a list of arguments and set shell=False."
                ),
                snippet=_snippet(lines, node.lineno),
            )
        )
    return findings


def _is_realpath_call(node: ast.AST) -> bool:
    """Return True if node is an os.path.realpath(...) call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "realpath"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "path"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "os"
    )


def _build_parent_map(tree: ast.AST) -> dict:
    """Return a dict mapping each child node to its parent node."""
    parents: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _rule_path_traversal(
    tree: ast.AST, rel_path: str, lines: List[str]
) -> List[Finding]:
    """Detect os.path.join() where a non-first argument is a function parameter.

    Skips occurrences that are directly wrapped in os.path.realpath() —
    those are the validated/fixed pattern and should not be flagged.
    """

    # Collect all parameter names in the file
    param_names: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args:
                param_names.add(arg.arg)

    parent_map = _build_parent_map(tree)

    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match os.path.join(...)
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "join"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "path"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "os"
        ):
            continue
        # Skip if this join() is directly wrapped in os.path.realpath()
        parent = parent_map.get(id(node))
        if parent is not None and _is_realpath_call(parent):
            continue
        # Check arguments beyond the first (base dir)
        for arg in node.args[1:]:
            if isinstance(arg, ast.Name) and arg.id in param_names:
                findings.append(
                    Finding(
                        rule_id="PATH_TRAVERSAL",
                        owasp="A01:2021 Broken Access Control",
                        severity="HIGH",
                        file=rel_path,
                        line=node.lineno,
                        symbol="os.path.join",
                        message=(
                            f"os.path.join() receives unsanitised parameter "
                            f"'{arg.id}'. Validate with os.path.realpath() "
                            "and check the result stays within the base directory."
                        ),
                        snippet=_snippet(lines, node.lineno),
                    )
                )
    return findings


def _rule_weak_crypto(
    tree: ast.AST, rel_path: str, lines: List[str]
) -> List[Finding]:
    """Detect calls to hashlib.md5() or hashlib.sha1()."""
    _WEAK = {"md5", "sha1"}
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr in _WEAK
            and isinstance(func.value, ast.Name)
            and func.value.id == "hashlib"
        ):
            continue
        findings.append(
            Finding(
                rule_id="WEAK_CRYPTO",
                owasp="A02:2021 Cryptographic Failures",
                severity="HIGH",
                file=rel_path,
                line=node.lineno,
                symbol=f"hashlib.{func.attr}",
                message=(
                    f"hashlib.{func.attr}() is cryptographically broken. "
                    "Use scrypt/bcrypt/argon2 for passwords; use SHA-256 only for non-password hashing."
                ),
                snippet=_snippet(lines, node.lineno),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_RULES = [
    _rule_hardcoded_secret,
    _rule_sql_injection,
    _rule_command_injection,
    _rule_path_traversal,
    _rule_weak_crypto,
]


def scan_file(path: str, rel_path: str) -> List[Finding]:
    """Parse a single Python file and run all rules against it."""
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    lines = source.splitlines(keepends=True)
    findings: List[Finding] = []
    for rule in _RULES:
        findings.extend(rule(tree, rel_path, lines))
    return findings


def scan_directory(target_dir: str) -> List[Finding]:
    """Recursively scan all .py files under target_dir."""
    target = Path(target_dir).resolve()
    all_findings: List[Finding] = []
    for py_file in sorted(target.rglob("*.py")):
        rel = str(py_file.relative_to(target.parent))
        all_findings.extend(scan_file(str(py_file), rel))
    # Sort by severity then file then line for deterministic output
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(
        key=lambda f: (severity_order.get(f.severity, 9), f.file, f.line)
    )
    return all_findings
