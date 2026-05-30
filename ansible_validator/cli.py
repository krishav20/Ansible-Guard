"""
AnsibleGuard CLI — validate Ansible playbooks from the command line.

Usage:
    ansible-guard playbook.yml
    ansible-guard playbooks/ --format json
    ansible-guard playbook.yml --ignore SEC002 BP007
    ansible-guard playbook.yml --severity high
"""

import argparse
import sys
import os

from ansible_validator.validator import AnsibleValidator, ValidationResult
from ansible_validator.reporters.terminal import TerminalReporter
from ansible_validator.reporters.json_reporter import JSONReporter


def parse_args():
    parser = argparse.ArgumentParser(
        prog="ansible-guard",
        description="AnsibleGuard — Static analysis and validation for Ansible playbooks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ansible-guard playbook.yml
  ansible-guard playbooks/ --format json
  ansible-guard site.yml --ignore SEC002 BP007
  ansible-guard site.yml --severity high
        """
    )
    parser.add_argument(
        "target",
        help="Playbook file or directory to validate"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--ignore", "-i",
        nargs="+",
        default=[],
        metavar="RULE_ID",
        help="Rule IDs to ignore (e.g. --ignore SEC002 BP007)"
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Only show findings at this severity or above"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="AnsibleGuard 0.1.0"
    )
    return parser.parse_args()


def filter_by_severity(results, min_severity):
    order = ["critical", "high", "medium", "low", "info"]
    if min_severity not in order:
        return results
    threshold = order.index(min_severity)
    return [r for r in results if order.index(r.severity) <= threshold]


def main():
    args = parse_args()
    validator = AnsibleValidator(ignore_rules=args.ignore)
    reporter_cls = TerminalReporter if args.format == "terminal" else JSONReporter
    reporter = reporter_cls()

    target = args.target
    exit_code = 0

    if os.path.isfile(target):
        try:
            results = validator.validate_file(target)
            if args.severity:
                results = filter_by_severity(results, args.severity)
            summary = validator.summary(results)
            print(reporter.report(results, target, summary))
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0:
                exit_code = 1
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            exit_code = 2

    elif os.path.isdir(target):
        all_results = validator.validate_directory(target)
        total_issues = 0
        for filepath, results in all_results.items():
            if args.severity:
                results = filter_by_severity(results, args.severity)
            summary = validator.summary(results)
            total_issues += summary.get("total", 0)
            print(reporter.report(results, filepath, summary))
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0:
                exit_code = 1
        if args.format == "terminal":
            print(f"Scanned {len(all_results)} playbook(s). Total findings: {total_issues}")
    else:
        print(f"Error: '{target}' is not a valid file or directory.", file=sys.stderr)
        exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
