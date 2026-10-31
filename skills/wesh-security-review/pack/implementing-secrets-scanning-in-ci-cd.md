---
name: implementing-secrets-scanning-in-ci-cd
description: Integrate gitleaks and trufflehog into CI/CD pipelines to detect leaked secrets before deployment
subdomain: devsecops
facing: config
mitre_attack:
- T1195
- T1554
- T1059.004
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
upstream: implementing-secrets-scanning-in-ci-cd@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9 or later
- gitleaks v8.x installed and available on PATH
- trufflehog v3.x installed and available on PATH
- Git repository or directory to scan
- Access to CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

## Steps

1. **Install scanning tools**: Install gitleaks via package manager or binary download. Install trufflehog via `brew install trufflehog` or download from GitHub releases.

2. **Configure gitleaks**: Create a `.gitleaks.toml` configuration file in repository root to define custom rules, allowlists, and path exclusions. Use `--config` flag to point to custom configs.

3. **Run gitleaks directory scan**: Execute `gitleaks dir --source . --report-format json --report-path gitleaks-report.json` to scan working directory and generate JSON report.

4. **Run trufflehog filesystem scan**: Execute `trufflehog filesystem /path/to/repo --json > trufflehog-report.json` to scan files and output JSON findings to report file.

5. **Parse and filter findings**: Use agent script to parse both JSON reports, filter findings by severity (critical, high, medium, low), and determine whether CI pipeline should pass or fail.

6. **Integrate into CI pipeline**: Add scanning step to your GitHub Actions workflow, GitLab CI config, or Jenkins pipeline as pre-deployment gate. Use `--exit-code` flag in gitleaks to control pipeline behavior.

7. **Configure pre-commit hooks**: Set up gitleaks as pre-commit hook using `gitleaks protect --staged` to catch secrets before they are committed.

8. **Review and triage findings**: Examine JSON output for false positives, add legitimate entries to `.gitleaksignore`, and rotate any confirmed leaked credentials immediately.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-secrets-scanning-in-ci-cd
