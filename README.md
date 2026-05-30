# AnsibleGuard

**Static analysis and security validation for Ansible playbooks.**

AnsibleGuard scans Ansible playbooks for security vulnerabilities, best practice violations, and maintainability issues — catching problems before they reach production. Built from real-world experience deploying infrastructure automation at enterprise scale.

```
$ ansible-guard playbook.yml

AnsibleGuard — playbook.yml
────────────────────────────────────────────────────────────
✖ [SEC001] CRITICAL  line 6
  Possible hardcoded password — use ansible-vault to encrypt sensitive values

● [SEC002] HIGH  [Install app]
  Task uses 'shell' module with shell operators — prefer specific modules

▲ [BP006] MEDIUM  [Deploy service]
  Potentially non-idempotent command 'apt-get install' — add a guard condition

────────────────────────────────────────────────────────────
Result: FAILED  |  1 critical  1 high  1 medium
```

---

## Motivation

In enterprise infrastructure automation, playbooks are deployed across hundreds of nodes. A single misconfigured task — a world-writable file permission, a hardcoded credential, a non-idempotent shell command — can cascade into a security incident or partial deployment failure.

Existing tools like `ansible-lint` focus on style. AnsibleGuard focuses on **security-first static analysis** with actionable, categorised findings designed for CI/CD integration.

---

## Features

| Category | What it checks |
|---|---|
| **Security** | Hardcoded secrets, unsafe shell usage, missing `no_log`, world-writable permissions, unvaulted credentials |
| **Best Practices** | Non-idempotent commands, deprecated modules, missing task names, missing FQCN |
| **Style** | Variable naming, task count per play, line length, tag consistency |

### Rule categories

- `SEC` — Security findings (critical/high severity)
- `BP` — Best practice violations (medium severity)
- `STY` — Style and maintainability (low/info severity)

---

## Installation

```bash
git clone https://github.com/yourusername/ansible-guard
cd ansible-guard
pip install -e .
```

**Requirements:** Python 3.8+, PyYAML

---

## Usage

**Validate a single playbook:**
```bash
ansible-guard playbook.yml
```

**Validate all playbooks in a directory:**
```bash
ansible-guard playbooks/
```

**Output as JSON (for CI/CD pipelines):**
```bash
ansible-guard playbook.yml --format json
```

**Only show high severity and above:**
```bash
ansible-guard playbook.yml --severity high
```

**Ignore specific rules:**
```bash
ansible-guard playbook.yml --ignore SEC002 BP007
```

---

## CI/CD Integration

AnsibleGuard exits with code `1` if any `critical` or `high` findings are detected, making it suitable as a pipeline gate.

**GitHub Actions example:**
```yaml
- name: Validate playbooks
  run: |
    pip install ansible-guard
    ansible-guard playbooks/ --severity high --format json
```

**Jenkins / GitLab CI:**
```bash
ansible-guard site.yml && echo "Playbook passed security checks"
```

---

## Architecture

```
ansible_validator/
├── models.py           # ValidationResult data model
├── validator.py        # Core engine — orchestrates checks
├── cli.py              # Command-line interface (argparse)
├── checks/
│   ├── security.py     # SEC rules — secrets, permissions, shell safety
│   ├── best_practices.py  # BP rules — idempotency, naming, deprecations
│   └── style.py        # STY rules — consistency, maintainability
└── reporters/
    ├── terminal.py     # Coloured human-readable output
    └── json_reporter.py   # Structured JSON for tooling
```

The check system is designed to be **extensible** — add a new check class in `checks/`, register it in `validator.py`, and it runs automatically. No configuration required.

---

## Security Rules Reference

| Rule | Severity | Description |
|---|---|---|
| SEC001 | Critical | Hardcoded secret detected (password, API key, token) |
| SEC002 | High/Medium | Unsafe shell/command module usage |
| SEC003 | High | Sensitive task missing `no_log: true` |
| SEC004 | High | World-writable file permissions (0777, 0666) |
| SEC005 | Medium | `become_password` not sourced from vault |

## Best Practice Rules Reference

| Rule | Severity | Description |
|---|---|---|
| BP001 | Medium | Play missing `name` field |
| BP002 | High | Play missing `hosts` field |
| BP003 | Low | `gather_facts` not explicitly set |
| BP004 | Medium | Task missing `name` field |
| BP005 | Medium | Deprecated module detected |
| BP006 | Medium | Non-idempotent command without guard |
| BP007 | Low | Short module name instead of FQCN |

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

12 tests covering security detection, best practice checks, ignore rules, and YAML parsing edge cases.

---

## Roadmap

- [ ] Custom rule definition via YAML config file
- [ ] Ansible Vault detection improvements
- [ ] HTML report output
- [ ] Pre-commit hook integration
- [ ] Role-level validation (not just playbooks)
- [ ] LLM-assisted fix suggestions (research direction)

---

## Background

Built by a software engineer with 3 years of enterprise infrastructure automation experience (Ansible, Python, Microsoft Power Platform) at a global IT services firm. This project explores the intersection of **static program analysis** and **infrastructure-as-code reliability** — a research area with growing relevance as organisations scale DevOps practices.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
