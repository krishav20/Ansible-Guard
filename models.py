"""
Data models for AnsibleGuard — separated to avoid circular imports.
"""

from typing import Dict, List


class ValidationResult:
    """Represents a single validation finding."""

    SEVERITIES = ["critical", "high", "medium", "low", "info"]

    def __init__(self, rule_id: str, severity: str, message: str,
                 file: str, line: int = None, task: str = None):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.file = file
        self.line = line
        self.task = task

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "task": self.task,
        }

    def __repr__(self):
        loc = f"line {self.line}" if self.line else "unknown line"
        return f"[{self.severity.upper()}] {self.rule_id}: {self.message} ({self.file}:{loc})"
