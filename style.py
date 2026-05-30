"""
Style and maintainability checks for Ansible playbooks.
Detects: overly long task lists, deeply nested vars, inconsistent naming,
missing tags on large playbooks.
"""

from typing import List, Any, Dict
from ansible_validator.models import ValidationResult

MAX_TASKS_PER_PLAY = 25
MAX_VAR_NAME_LENGTH = 50


class StyleChecks:
    """
    Style and maintainability checks.
    Rule IDs: STY001–STY010
    """

    def run(self, playbook: Any, filepath: str, raw_content: str) -> List[ValidationResult]:
        results = []
        if not isinstance(playbook, list):
            return results

        results.extend(self._check_line_length(raw_content, filepath))

        for play in playbook:
            if not isinstance(play, dict):
                continue
            tasks = play.get("tasks", [])
            results.extend(self._check_task_count(tasks, play, filepath))
            results.extend(self._check_var_naming(play, filepath))
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                results.extend(self._check_tag_usage(task, tasks, filepath))

        return results

    def _check_line_length(self, content: str, filepath: str) -> List[ValidationResult]:
        results = []
        for i, line in enumerate(content.splitlines(), start=1):
            if len(line) > 160:
                results.append(ValidationResult(
                    rule_id="STY001",
                    severity="low",
                    message=f"Line {i} is {len(line)} characters — consider breaking long lines for readability (max 160)",
                    file=filepath,
                    line=i,
                ))
        return results

    def _check_task_count(self, tasks: List, play: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        if len(tasks) > MAX_TASKS_PER_PLAY:
            results.append(ValidationResult(
                rule_id="STY002",
                severity="low",
                message=f"Play '{play.get('name', 'unnamed')}' has {len(tasks)} tasks — consider splitting into roles or included task files for maintainability",
                file=filepath,
            ))
        return results

    def _check_var_naming(self, play: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        vars_section = play.get("vars", {})
        if not isinstance(vars_section, dict):
            return results
        for var_name in vars_section:
            if "-" in var_name:
                results.append(ValidationResult(
                    rule_id="STY003",
                    severity="low",
                    message=f"Variable '{var_name}' uses hyphens — use underscores for variable names (e.g. '{var_name.replace('-', '_')}')",
                    file=filepath,
                ))
            if len(var_name) > MAX_VAR_NAME_LENGTH:
                results.append(ValidationResult(
                    rule_id="STY004",
                    severity="low",
                    message=f"Variable name '{var_name}' is very long ({len(var_name)} chars) — consider a shorter name",
                    file=filepath,
                ))
        return results

    def _check_tag_usage(self, task: Dict, all_tasks: List, filepath: str) -> List[ValidationResult]:
        """If the play has many tasks and some use tags, all should use tags."""
        results = []
        if len(all_tasks) > 10:
            tagged_tasks = sum(1 for t in all_tasks if isinstance(t, dict) and "tags" in t)
            if tagged_tasks > 0 and "tags" not in task and "name" in task:
                results.append(ValidationResult(
                    rule_id="STY005",
                    severity="info",
                    message=f"Task '{task['name']}' has no tags — for consistency, tag all tasks when some tasks use tags",
                    file=filepath,
                    task=task["name"],
                ))
        return results
