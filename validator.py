"""
Core validation engine for AnsibleGuard.
"""

import yaml
import os
from pathlib import Path
from typing import List, Dict, Any

from ansible_validator.models import ValidationResult
from ansible_validator.checks.security import SecurityChecks
from ansible_validator.checks.best_practices import BestPracticeChecks
from ansible_validator.checks.style import StyleChecks


class AnsibleValidator:
    """Main validator — loads playbooks and runs all registered checks."""

    def __init__(self, ignore_rules: List[str] = None):
        self.ignore_rules = ignore_rules or []
        self.check_modules = [
            SecurityChecks(),
            BestPracticeChecks(),
            StyleChecks(),
        ]

    def validate_file(self, filepath: str) -> List[ValidationResult]:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {filepath}")
        if path.suffix not in (".yml", ".yaml"):
            raise ValueError(f"File must be YAML: {filepath}")
        try:
            with open(filepath, "r") as f:
                content = f.read()
                playbook = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return [ValidationResult(rule_id="PARSE001", severity="critical",
                                     message=f"YAML parse error: {e}", file=filepath)]
        if playbook is None:
            return [ValidationResult(rule_id="PARSE002", severity="high",
                                     message="Playbook is empty or null", file=filepath)]
        results = []
        for check_module in self.check_modules:
            results.extend(check_module.run(playbook, filepath, content))
        results = [r for r in results if r.rule_id not in self.ignore_rules]
        severity_order = {s: i for i, s in enumerate(ValidationResult.SEVERITIES)}
        results.sort(key=lambda r: severity_order.get(r.severity, 99))
        return results

    def validate_directory(self, dirpath: str) -> Dict[str, List[ValidationResult]]:
        results = {}
        for root, _, files in os.walk(dirpath):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    full_path = os.path.join(root, file)
                    results[full_path] = self.validate_file(full_path)
        return results

    def summary(self, results: List[ValidationResult]) -> Dict[str, int]:
        counts = {s: 0 for s in ValidationResult.SEVERITIES}
        for r in results:
            if r.severity in counts:
                counts[r.severity] += 1
        counts["total"] = len(results)
        return counts
