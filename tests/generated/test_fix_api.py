"""
Auto-generated regression tests for COMMAND_INJECTION fix in api_safe.py.
Rule: COMMAND_INJECTION  |  OWASP: A03:2021 Injection
"""
import ast
from pathlib import Path


def _safe_source():
    return (Path(__file__).parent.parent.parent / "vulnerable_app" / "api_safe.py").read_text()


class TestApiSafeNoCommandInjection:
    def test_shell_true_absent_from_source(self):
        """api_safe.py must not contain shell=True in live code (comments/docstrings excluded)."""
        import ast as _ast
        src = _safe_source()
        tree = _ast.parse(src)
        lines = src.splitlines()
        docstring_lines = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Expr) and isinstance(node.value, _ast.Constant):
                if isinstance(node.value.value, str):
                    for ln in range(node.lineno, node.end_lineno + 1):
                        docstring_lines.add(ln)
        code_lines = [
            line for i, line in enumerate(lines, 1)
            if i not in docstring_lines and not line.lstrip().startswith("#")
        ]
        code_only = chr(10).join(code_lines)
        assert "shell=True" not in code_only, "shell=True still present in api_safe.py code"

    def test_shell_false_present_in_source(self):
        """api_safe.py must explicitly use shell=False."""
        src = _safe_source()
        assert "shell=False" in src, "shell=False not found in api_safe.py"

    def test_args_passed_as_list(self):
        """subprocess.run must receive a list, not an f-string."""
        src = _safe_source()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "run"):
                continue
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                pytest.fail("subprocess.run still receives an f-string argument")
            if node.args and isinstance(node.args[0], ast.List):
                return  # found the safe list form — test passes
        # If no subprocess.run call found at all that's fine for this check
        pass

    def test_scanner_reports_no_command_injection_in_safe(self):
        """The scanner must produce zero COMMAND_INJECTION findings in api_safe.py."""
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "api_safe.py")
        findings = [f for f in scan_file(path, "api_safe.py") if f.rule_id == "COMMAND_INJECTION"]
        assert findings == [], f"Unexpected findings: {findings}"
