"""
sentinel/models.py — shared data types for the pipeline.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single security or bug finding produced by the scanner."""

    rule_id: str          # e.g. "SQL_INJECTION"
    owasp: str            # e.g. "A03:2021 Injection"
    severity: str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    file: str             # relative path to the source file
    line: int             # 1-based line number of the finding
    symbol: str           # function or variable name where the flaw lives
    message: str          # short human-readable description
    snippet: str = ""     # the offending source line(s)
    explanation: str = "" # populated by the explainer
