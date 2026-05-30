"""
JSON reporter — structured output for CI/CD pipeline integration.
"""

import json
from typing import List, Dict
from ansible_validator.models import ValidationResult


class JSONReporter:
    """Renders validation results as JSON — useful for CI pipelines and tooling."""

    def report(self, results: List[ValidationResult], filepath: str, summary: Dict) -> str:
        output = {
            "file": filepath,
            "summary": summary,
            "passed": summary.get("total", 0) == 0,
            "findings": [r.to_dict() for r in results],
        }
        return json.dumps(output, indent=2)