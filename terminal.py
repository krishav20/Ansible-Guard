"""
Terminal reporter — coloured, human-readable output for CLI use.
"""

from typing import List, Dict
from ansible_validator.models import ValidationResult


class TerminalReporter:
    """Renders validation results as coloured terminal output."""

    COLOURS = {
        "critical": "\033[91m",  # bright red
        "high":     "\033[31m",  # red
        "medium":   "\033[33m",  # yellow
        "low":      "\033[36m",  # cyan
        "info":     "\033[37m",  # grey
        "reset":    "\033[0m",
        "bold":     "\033[1m",
        "green":    "\033[92m",
        "header":   "\033[95m",
    }

    ICONS = {
        "critical": "✖",
        "high":     "●",
        "medium":   "▲",
        "low":      "◆",
        "info":     "ℹ",
    }

    def report(self, results: List[ValidationResult], filepath: str, summary: Dict) -> str:
        lines = []
        c = self.COLOURS

        lines.append(f"\n{c['bold']}{c['header']}AnsibleGuard — {filepath}{c['reset']}")
        lines.append("─" * 60)

        if not results:
            lines.append(f"{c['green']}✔  No issues found.{c['reset']}\n")
            return "\n".join(lines)

        for r in results:
            col = c.get(r.severity, c["reset"])
            icon = self.ICONS.get(r.severity, "•")
            task_str = f" [{r.task}]" if r.task else ""
            line_str = f" line {r.line}" if r.line else ""
            lines.append(
                f"{col}{icon} [{r.rule_id}] {r.severity.upper()}{c['reset']}"
                f"{c['bold']}{task_str}{c['reset']}{line_str}"
            )
            lines.append(f"  {r.message}")
            lines.append("")

        lines.append("─" * 60)
        lines.append(self._summary_line(summary))
        lines.append("")
        return "\n".join(lines)

    def _summary_line(self, summary: Dict) -> str:
        c = self.COLOURS
        parts = []
        colour_map = {
            "critical": c["critical"],
            "high": c["high"],
            "medium": c["medium"],
            "low": c["low"],
            "info": c["info"],
        }
        for severity, col in colour_map.items():
            count = summary.get(severity, 0)
            if count:
                parts.append(f"{col}{count} {severity}{c['reset']}")
        total = summary.get("total", 0)
        status = f"{c['green']}PASSED{c['reset']}" if total == 0 else f"{c['high']}FAILED{c['reset']}"
        return f"Result: {status}  |  " + "  ".join(parts) if parts else f"Result: {status}"
