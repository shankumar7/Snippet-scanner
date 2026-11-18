"""Data structures shared by the rule set and the scan engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

# OWASP Top 10 (2021) categories and their default severity.
CATEGORIES = {
    "A01": ("A01:2021 - Broken Access Control", "High"),
    "A02": ("A02:2021 - Cryptographic Failures", "High"),
    "A03": ("A03:2021 - Injection", "High"),
    "A04": ("A04:2021 - Insecure Design", "Medium"),
    "A05": ("A05:2021 - Security Misconfiguration", "Medium"),
    "A06": ("A06:2021 - Vulnerable and Outdated Components", "Medium"),
    "A07": ("A07:2021 - Identification and Authentication Failures", "High"),
    "A08": ("A08:2021 - Software and Data Integrity Failures", "High"),
    "A09": ("A09:2021 - Security Logging and Monitoring Failures", "Low"),
    "A10": ("A10:2021 - Server-Side Request Forgery (SSRF)", "High"),
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass(frozen=True)
class Rule:
    """A single line-oriented detection rule.

    ``patterns`` are matched against each line independently. A rule reports
    at most one finding per line. Rules whose pattern must span lines set
    ``multiline=True`` and are matched against the whole document instead.
    """

    id: str
    category: str  # key into CATEGORIES, e.g. "A03"
    title: str
    description: str
    suggestion: str
    patterns: Tuple["re.Pattern[str]", ...]
    severity: Optional[str] = None  # overrides the category default
    multiline: bool = False

    @property
    def owasp_category(self) -> str:
        return CATEGORIES[self.category][0]

    @property
    def effective_severity(self) -> str:
        return self.severity or CATEGORIES[self.category][1]


@dataclass
class Finding:
    """One reported issue. ``to_dict`` produces the public API shape."""

    rule_id: str
    issue: str
    severity: str
    description: str
    suggestion: str
    owasp_category: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "issue": self.issue,
            "severity": self.severity,
            "description": self.description,
            "suggestion": self.suggestion,
            "owasp_category": self.owasp_category,
            "line_number": self.line_number,
            "snippet": self.snippet,
        }
