---
name: implementing-secret-scanning-with-gitleaks
description: This skill covers implementing Gitleaks for detecting and preventing hardcoded secrets in git repositories.
subdomain: devsecops
facing: config
mitre_attack:
- T1195
- T1554
- T1059.004
- T1003
- T1110
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
upstream: implementing-secret-scanning-with-gitleaks@54a7988 Apache-2.0, modified by wesh
---
Not for: detecting secrets in running applications or memory (use runtime secret detection), for managing secrets after detection (use Vault or AWS Secrets Manager), or for scanning container images (use Trivy or Grype).

## Prerequisites

- Gitleaks v8.18+ installed via binary, Go install, or Docker
- Pre-commit framework installed for local hook integration
- Git repository with history to scan
- CI/CD platform access (GitHub Actions, GitLab CI, or equivalent)

## Workflow

### Step 1: Install and Run Initial Repository Scan

Perform baseline scan of repository to identify all existing secrets in git history.

```bash
# Install Gitleaks
brew install gitleaks  # macOS
# or download binary from https://github.com/gitleaks/gitleaks/releases
# Scan entire git history for secrets
gitleaks detect --source . --report-format json --report-path gitleaks-report.json -v
# Scan only staged changes (for pre-commit)
gitleaks protect --staged --report-format json --report-path gitleaks-staged.json
# Scan specific commit range
gitleaks detect --source . --log-opts="HEAD~10..HEAD" --report-format json
# Scan without git history (filesystem only)
gitleaks detect --source . --no-git --report-format json
```

### Step 2: Configure Pre-Commit Hook

Set up Gitleaks as pre-commit hook to prevent secrets from being committed.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        name: gitleaks
        description: Detect hardcoded secrets using Gitleaks
        entry: gitleaks protect --staged --verbose --redact
        language: golang
        pass_filenames: false
```

```bash
# Install pre-commit framework
pip install pre-commit
# Install hooks defined in .pre-commit-config.yaml
pre-commit install
# Run against all files (not just staged)
pre-commit run gitleaks --all-files
# Test the hook with a deliberate secret
echo 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' >> test.txt
git add test.txt
git commit -m "test"  # Should be blocked by gitleaks
```

### Step 3: Integrate into GitHub Actions

```yaml
# .github/workflows/secret-scanning.yml
name: Secret Scanning
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
jobs:
  gitleaks:
    name: Gitleaks Secret Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for comprehensive scanning
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # Required for gitleaks-action v2
      # Alternative: Run Gitleaks directly
      - name: Install Gitleaks
        run: |
          wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
          tar -xzf gitleaks_8.21.2_linux_x64.tar.gz
          chmod +x gitleaks
      - name: Scan for secrets
        run: |
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            ./gitleaks detect \
              --source . \
              --log-opts="${{ github.event.pull_request.base.sha }}..${{ github.event.pull_request.head.sha }}" \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1
          else
            ./gitleaks detect \
              --source . \
              --report-format sarif \
              --report-path gitleaks.sarif \
              --exit-code 1 \
              --baseline-path .gitleaks-baseline.json
          fi
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks
```

### Step 4: Author Custom Detection Rules

Create organization-specific rules for internal secret patterns.

```toml
# .gitleaks.toml
title = "Organization Gitleaks Configuration"
[extend]
useDefault = true  # Include all default rules
# Custom rule for internal API tokens
[[rules]]
id = "internal-api-token"
description = "Internal API token for service-to-service auth"
regex = '''(?i)x-internal-token["\s:=]+["\']?([a-zA-Z0-9_\-]{40,})["\']?'''
entropy = 3.5
keywords = ["x-internal-token"]
tags = ["internal", "api"]
[[rules]]
id = "database-connection-string"
description = "Database connection string with embedded credentials"
regex = '''(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+/\w+'''
keywords = ["postgres://", "mysql://", "mongodb://", "redis://"]
tags = ["database", "credentials"]
[[rules]]
id = "jwt-secret"
description = "JWT signing secret"
regex = '''(?i)(jwt[_-]?secret|jwt[_-]?key)["\s:=]+["\']?([a-zA-Z0-9/+_\-]{32,})["\']?'''
entropy = 3.0
keywords = ["jwt_secret", "jwt-secret", "jwt_key", "jwt-key"]
# Allowlist for test files and known safe patterns
[allowlist]
description = "Global allowlist"
paths = [
  '''(^|/)test(s)?/''',
  '''(^|/)spec/''',
  '''\.test\.(js|ts|py)$''',
  '''\.spec\.(js|ts|py)$''',
  '''__mocks__/''',
  '''fixtures/''',
  '''(^|/)vendor/''',
  '''node_modules/'''
]
regexes = [
  '''EXAMPLE''',
  '''example\.com''',
  '''test[-_]?(key|secret|token|password)''',
  '''(?i)placeholder''',
  '''000000+'''
]
```

### Step 5: Manage Baselines for Existing Repositories

Create baseline of known findings to avoid blocking development while historical secrets are being rotated.

```bash
# Generate baseline from current state
gitleaks detect --source . --report-format json --report-path .gitleaks-baseline.json
# Subsequent scans compare against baseline (only new findings trigger failures)
gitleaks detect --source . --baseline-path .gitleaks-baseline.json --exit-code 1
# Review baseline periodically and remove entries as secrets are rotated
cat .gitleaks-baseline.json | python3 -m json.tool | head -50
```

### Step 6: Remediate Exposed Secrets

When secret is detected, follow rotation and history cleanup procedure.

```bash
# 1. Immediately rotate the exposed credential
#    - Revoke the old API key/token in the service provider
#    - Generate a new credential
#    - Store the new credential in a secrets manager
# 2. Remove secret from git history using git-filter-repo
pip install git-filter-repo
# Create expressions file for secrets to remove
cat > /tmp/expressions.txt << 'EOF'
regex:AKIA[0-9A-Z]{16}==>REDACTED_AWS_KEY
regex:(?i)password\s*=\s*"[^"]*"==>password="REDACTED"
EOF
git filter-repo --replace-text /tmp/expressions.txt --force
# 3. Force-push the cleaned history (coordinate with team)
# git push --force --all  # WARNING: Requires team coordination
# 4. Add the secret pattern to .gitleaks.toml rules
# 5. Update the baseline file to remove the resolved finding
```

## Key Concepts

| Term | Definition |
|------|------------|
| Secret | Any credential, token, key, or sensitive string that should not appear in source code |
| Pre-commit Hook | Git hook that runs before commit is created, blocking commits containing detected secrets |
| Entropy | Measure of randomness in string; high-entropy strings are more likely to be secrets |
| Baseline | Snapshot of existing findings used to differentiate new secrets from pre-existing ones |
| Allowlist | Configuration specifying paths, patterns, or commits to exclude from detection |
| SARIF | Static Analysis Results Interchange Format for uploading findings to security dashboards |
| git-filter-repo | Tool for rewriting git history to remove sensitive data from all commits |

## Tools & Systems

- **Gitleaks**: Open-source secret detection tool supporting pre-commit hooks, CI/CD, and historical scanning
- **pre-commit**: Framework for managing and maintaining multi-language pre-commit hooks
- **git-filter-repo**: History rewriting tool for removing secrets from git history
- **TruffleHog**: Alternative secret scanner with verified secret detection capabilities
- **GitHub Secret Scanning**: Native GitHub feature that detects secrets matching partner patterns

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-secret-scanning-with-gitleaks
