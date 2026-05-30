"""
Tests for AnsibleGuard validation checks.
"""

import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ansible_validator.validator import AnsibleValidator


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_playbooks")


class TestSecurityChecks:

    def setup_method(self):
        self.validator = AnsibleValidator()

    def test_detects_hardcoded_password(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- hosts: all
  vars:
    db_password: mysecretpassword123
  tasks:
    - name: Do something
      ansible.builtin.debug:
        msg: hello
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "SEC001" in rule_ids

    def test_detects_unsafe_shell_with_pipe(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- hosts: all
  tasks:
    - name: Install app
      shell: apt-get install nginx | tee install.log
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "SEC002" in rule_ids

    def test_no_log_warning_on_sensitive_task(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- hosts: all
  tasks:
    - name: Set password for database
      ansible.builtin.user:
        name: dbadmin
        password: "{{ db_pass }}"
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "SEC003" in rule_ids

    def test_world_writable_permission_flagged(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- hosts: all
  tasks:
    - name: Copy file
      ansible.builtin.copy:
        src: app.conf
        dest: /etc/app.conf
        mode: "0777"
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "SEC004" in rule_ids

    def test_vault_values_not_flagged(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- hosts: all
  vars:
    db_password: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      61383761653263326566343263363766
  tasks:
    - name: Do something
      ansible.builtin.debug:
        msg: hello
""")
        results = self.validator.validate_file(str(playbook))
        sec001_results = [r for r in results if r.rule_id == "SEC001"]
        assert len(sec001_results) == 0


class TestBestPracticeChecks:

    def setup_method(self):
        self.validator = AnsibleValidator()

    def test_missing_task_name_flagged(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- name: Test play
  hosts: all
  gather_facts: false
  tasks:
    - ansible.builtin.debug:
        msg: no name here
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "BP004" in rule_ids

    def test_deprecated_module_flagged(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- name: Test play
  hosts: all
  gather_facts: false
  tasks:
    - name: Include tasks
      include: other_tasks.yml
""")
        results = self.validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "BP005" in rule_ids

    def test_good_playbook_has_no_critical_or_high(self):
        good_playbook = os.path.join(SAMPLE_DIR, "good_playbook.yml")
        if os.path.exists(good_playbook):
            results = self.validator.validate_file(good_playbook)
            critical_high = [r for r in results if r.severity in ("critical", "high")]
            assert len(critical_high) == 0

    def test_bad_playbook_has_findings(self):
        bad_playbook = os.path.join(SAMPLE_DIR, "bad_playbook.yml")
        if os.path.exists(bad_playbook):
            results = self.validator.validate_file(bad_playbook)
            assert len(results) > 0


class TestIgnoreRules:

    def test_ignored_rules_not_in_results(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("""
- name: Test
  hosts: all
  tasks:
    - name: Run shell
      shell: ls -la
""")
        validator = AnsibleValidator(ignore_rules=["SEC002"])
        results = validator.validate_file(str(playbook))
        rule_ids = [r.rule_id for r in results]
        assert "SEC002" not in rule_ids


class TestYAMLParsing:

    def setup_method(self):
        self.validator = AnsibleValidator()

    def test_invalid_yaml_returns_parse_error(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("{ invalid: yaml: content: [}")
        results = self.validator.validate_file(str(playbook))
        assert results[0].rule_id == "PARSE001"
        assert results[0].severity == "critical"

    def test_empty_playbook_returns_error(self, tmp_path):
        playbook = tmp_path / "test.yml"
        playbook.write_text("")
        results = self.validator.validate_file(str(playbook))
        assert any(r.rule_id in ("PARSE002",) for r in results)
