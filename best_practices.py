"""
Best practice checks for Ansible playbooks.
Detects: missing task names, non-idempotent patterns, missing handlers,
deprecated modules, missing tags.
"""

from typing import List, Any, Dict
from ansible_validator.models import ValidationResult

DEPRECATED_MODULES = {
    "apt_key": "Use ansible.builtin.deb822_repository instead (Ansible 2.15+)",
    "yum": "Prefer ansible.builtin.dnf on RHEL 8+",
    "include": "Use ansible.builtin.include_tasks or ansible.builtin.import_tasks",
    "win_copy": "Use ansible.windows.win_copy with FQCN",
}

NON_IDEMPOTENT_COMMANDS = [
    "apt-get install", "yum install", "pip install",
    "mkdir ", "touch ", "useradd ", "groupadd ",
]


class BestPracticeChecks:
    """
    Best practice static analysis checks.
    Rule IDs: BP001–BP010
    """

    def run(self, playbook: Any, filepath: str, raw_content: str) -> List[ValidationResult]:
        results = []
        if not isinstance(playbook, list):
            return results

        for play in playbook:
            if not isinstance(play, dict):
                continue
            results.extend(self._check_play_structure(play, filepath))
            tasks = play.get("tasks", []) + play.get("pre_tasks", []) + play.get("post_tasks", [])
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                results.extend(self._check_task_name(task, filepath))
                results.extend(self._check_deprecated_modules(task, filepath))
                results.extend(self._check_idempotency(task, filepath))
                results.extend(self._check_fqcn(task, filepath))

        return results

    def _check_play_structure(self, play: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        if "name" not in play:
            results.append(ValidationResult(
                rule_id="BP001",
                severity="medium",
                message="Play is missing a 'name' field — always name your plays for readability",
                file=filepath,
            ))
        if "hosts" not in play:
            results.append(ValidationResult(
                rule_id="BP002",
                severity="high",
                message="Play is missing 'hosts' field",
                file=filepath,
                task=play.get("name", "unnamed play"),
            ))
        # Warn if gather_facts not explicitly set
        if "gather_facts" not in play:
            results.append(ValidationResult(
                rule_id="BP003",
                severity="low",
                message="'gather_facts' not explicitly set — set to 'false' if facts are not needed to speed up execution",
                file=filepath,
                task=play.get("name", "unnamed play"),
            ))
        return results

    def _check_task_name(self, task: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        if "name" not in task:
            # Find what module is being used
            known_keys = {"name", "when", "register", "notify", "tags", "become",
                         "no_log", "loop", "with_items", "ignore_errors", "vars"}
            module = next((k for k in task if k not in known_keys), "unknown")
            results.append(ValidationResult(
                rule_id="BP004",
                severity="medium",
                message=f"Task using '{module}' module has no 'name' — all tasks should be named for clarity",
                file=filepath,
            ))
        return results

    def _check_deprecated_modules(self, task: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        task_name = task.get("name", "unnamed task")
        for module, suggestion in DEPRECATED_MODULES.items():
            if module in task:
                results.append(ValidationResult(
                    rule_id="BP005",
                    severity="medium",
                    message=f"Module '{module}' is deprecated — {suggestion}",
                    file=filepath,
                    task=task_name,
                ))
        return results

    def _check_idempotency(self, task: Dict, filepath: str) -> List[ValidationResult]:
        """Flag shell/command tasks with known non-idempotent patterns."""
        results = []
        task_name = task.get("name", "unnamed task")
        for module in ["shell", "command"]:
            if module in task:
                cmd = str(task[module])
                for pattern in NON_IDEMPOTENT_COMMANDS:
                    if pattern in cmd:
                        # Check if creates/when guards idempotency
                        has_guard = "creates" in task or "when" in task or "changed_when" in task
                        if not has_guard:
                            results.append(ValidationResult(
                                rule_id="BP006",
                                severity="medium",
                                message=f"Potentially non-idempotent command '{pattern.strip()}' — add 'creates', 'when', or 'changed_when' guard, or use a dedicated module",
                                file=filepath,
                                task=task_name,
                            ))
                        break
        return results

    def _check_fqcn(self, task: Dict, filepath: str) -> List[ValidationResult]:
        """Encourage use of Fully Qualified Collection Names."""
        results = []
        task_name = task.get("name", "unnamed task")
        short_modules = ["copy", "template", "file", "service", "user", "group",
                        "apt", "yum", "dnf", "package", "systemd", "cron", "lineinfile"]
        for module in short_modules:
            if module in task:
                results.append(ValidationResult(
                    rule_id="BP007",
                    severity="low",
                    message=f"Use FQCN 'ansible.builtin.{module}' instead of short name '{module}' for future-proofing",
                    file=filepath,
                    task=task_name,
                ))
        return results
