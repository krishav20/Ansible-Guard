"""
Security checks for Ansible playbooks.
Detects: hardcoded secrets, unsafe shell usage, world-writable permissions,
missing no_log, unencrypted sensitive vars.
"""

import re
from typing import List, Any, Dict
from ansible_validator.models import ValidationResult


SECRET_PATTERNS = [
    (r'password\s*[:=]\s*["\']?[A-Za-z0-9@#$%^&+=!]{6,}["\']?', "Possible hardcoded password"),
    (r'secret\s*[:=]\s*["\']?[A-Za-z0-9@#$%^&+=!]{6,}["\']?', "Possible hardcoded secret"),
    (r'api_key\s*[:=]\s*["\']?[A-Za-z0-9\-_]{16,}["\']?', "Possible hardcoded API key"),
    (r'token\s*[:=]\s*["\']?[A-Za-z0-9\-_\.]{20,}["\']?', "Possible hardcoded token"),
    (r'aws_access_key_id\s*[:=]\s*["\']?[A-Z0-9]{16,}["\']?', "Possible hardcoded AWS key"),
    (r'private_key\s*[:=]', "Possible private key reference without vault"),
]

UNSAFE_MODULES = ["command", "shell", "raw"]

WORLD_WRITABLE_MODES = ["0777", "0666", "777", "666"]


class SecurityChecks:
    """
    Security-focused static analysis checks.
    Rule IDs: SEC001–SEC010
    """

    def run(self, playbook: Any, filepath: str, raw_content: str) -> List[ValidationResult]:
        results = []
        results.extend(self._check_hardcoded_secrets(raw_content, filepath))

        if not isinstance(playbook, list):
            return results

        for play in playbook:
            if not isinstance(play, dict):
                continue
            tasks = play.get("tasks", []) + play.get("pre_tasks", []) + play.get("post_tasks", [])
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                results.extend(self._check_unsafe_shell(task, filepath))
                results.extend(self._check_no_log(task, filepath))
                results.extend(self._check_file_permissions(task, filepath))
                results.extend(self._check_become_password(task, filepath))

        return results

    def _check_hardcoded_secrets(self, content: str, filepath: str) -> List[ValidationResult]:
        results = []
        for i, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Skip vault-encrypted values
            if "!vault" in line or "{{ vault" in line.lower():
                continue
            # Skip Jinja2 variables ({{ var }})
            if re.search(r'\{\{.*\}\}', line):
                continue
            for pattern, message in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append(ValidationResult(
                        rule_id="SEC001",
                        severity="critical",
                        message=f"{message} — use ansible-vault to encrypt sensitive values",
                        file=filepath,
                        line=i,
                    ))
                    break
        return results

    def _check_unsafe_shell(self, task: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        task_name = task.get("name", "unnamed task")
        for module in UNSAFE_MODULES:
            if module in task:
                cmd = task[module]
                if isinstance(cmd, str):
                    # Flag piped or chained commands as higher risk
                    if any(op in cmd for op in ["|", "&&", "||", ";"]):
                        results.append(ValidationResult(
                            rule_id="SEC002",
                            severity="high",
                            message=f"Task uses '{module}' module with shell operators — prefer specific modules (ansible.builtin.apt, ansible.builtin.copy, etc.)",
                            file=filepath,
                            task=task_name,
                        ))
                    else:
                        results.append(ValidationResult(
                            rule_id="SEC002",
                            severity="medium",
                            message=f"Task uses '{module}' module — consider using a dedicated Ansible module instead",
                            file=filepath,
                            task=task_name,
                        ))
        return results

    def _check_no_log(self, task: Dict, filepath: str) -> List[ValidationResult]:
        """Warn when tasks handling sensitive data don't set no_log: true."""
        results = []
        task_name = task.get("name", "unnamed task").lower()
        sensitive_keywords = ["password", "secret", "token", "key", "credential", "auth"]

        has_sensitive_name = any(kw in task_name for kw in sensitive_keywords)
        has_no_log = task.get("no_log", False)

        if has_sensitive_name and not has_no_log:
            results.append(ValidationResult(
                rule_id="SEC003",
                severity="high",
                message="Task name suggests sensitive data but 'no_log: true' is not set — task output may expose secrets in logs",
                file=filepath,
                task=task.get("name", "unnamed task"),
            ))
        return results

    def _check_file_permissions(self, task: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        task_name = task.get("name", "unnamed task")
        for module in ["file", "copy", "template", "ansible.builtin.file", "ansible.builtin.copy", "ansible.builtin.template"]:
            if module in task:
                mode = str(task[module].get("mode", "")) if isinstance(task[module], dict) else ""
                if any(m in mode for m in WORLD_WRITABLE_MODES):
                    results.append(ValidationResult(
                        rule_id="SEC004",
                        severity="high",
                        message=f"World-writable or world-readable permission '{mode}' detected — use least-privilege permissions",
                        file=filepath,
                        task=task_name,
                    ))
        return results

    def _check_become_password(self, task: Dict, filepath: str) -> List[ValidationResult]:
        results = []
        task_name = task.get("name", "unnamed task")
        if task.get("become", False) and "become_password" in str(task):
            results.append(ValidationResult(
                rule_id="SEC005",
                severity="medium",
                message="'become_password' found in task — ensure this is sourced from vault, not plaintext",
                file=filepath,
                task=task_name,
            ))
        return results
