---
name: detecting-dependency-confusion
description: Detect and prevent dependency confusion (public-over-private package name resolution) in npm, PyPI, and Maven by enumerating claimable internal package names with tools like `confused` and OWASP `dep-scan`, then enforcing source restrictions via `.npmrc`, `pip.conf`/`pyproject.toml`, and Maven `settings.xml`.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195.001
nist_csf:
- ID.RA-09
upstream: detecting-dependency-confusion@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Go 1.20+ to install `confused`:
  ```bash
  go install github.com/visma-prodsec/confused@latest
  # binary lands in $(go env GOPATH)/bin/confused
  ```
- Python 3.10+ for OWASP dep-scan:
  ```bash
  pip install owasp-depscan
  # or container: docker pull ghcr.io/owasp-dep-scan/dep-scan
  ```
- Node.js + npm (for `.npmrc` and `npm config` remediation) and access to your private registry (Artifactory, Nexus, Azure Artifacts, GitHub Packages, AWS CodeArtifact).
- Read access to repositories / lockfiles being assessed and write access to your private registry for defensive registration.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Core technique — attacker substitutes malicious public package for internal dependency. |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Broader category covering compromised build artifacts produced once confusion succeeds. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | npm `preinstall`/`postinstall` lifecycle scripts execute attacker JavaScript on resolution. |
| T1071.001 | Application Layer Protocol: Web Protocols | Substituted package beacons stolen environment/credentials to attacker HTTP(S) endpoint. |

## Workflow

### 1. Inventory manifests across codebase
Locate every dependency manifest so nothing is missed.
```bash
# Find all supported manifests in a monorepo
find . -type f \( \
  -name package.json -o \
  -name requirements.txt -o \
  -name pom.xml -o \
  -name composer.json -o \
  -name Gemfile.lock \
\) -not -path '*/node_modules/*' -print
```

### 2. Scan npm manifests with confused
`confused` reads manifest and reports every dependency name **not found** on public registry — those are candidates for confusion.
```bash
# npm (default language is npm)
confused -l npm package.json
# Treat your known-good scopes as secure to suppress false positives (supports wildcards)
confused -l npm -s '@acme/*,@acme-internal/*' package.json
# Verbose, to see each lookup
confused -l npm -v package.json
```

### 3. Scan PyPI, Maven, Composer, and RubyGems manifests
The `-l` flag selects ecosystem; each maps to its standard manifest file.
```bash
confused -l pip requirements.txt          # PyPI  -> requirements.txt
confused -l mvn pom.xml                    # Maven -> pom.xml
confused -l composer composer.json        # PHP   -> composer.json
confused -l rubygems Gemfile.lock         # Ruby  -> Gemfile.lock
```

### 4. Cross-check with OWASP dep-scan private-namespace mode
dep-scan confirms confusion exposure for declared private namespaces and folds it into broader risk audit.
```bash
# Flag private namespaces accidentally claimable on public registries
depscan --src $PWD --reports-dir ./reports \
  --private-ns acme,acme_internal,@acme
# Enable deep package risk audit (npm + pypi): typosquats, takeover risk, etc.
depscan --src $PWD --reports-dir ./reports --risk-audit
```

### 5. Triage candidates and confirm claimability
For each flagged name, verify it is genuinely absent on public registry (404 means claimable).
```bash
# npm: a 404 status means the name is unregistered on the public registry
curl -s -o /dev/null -w "%{http_code}\n" https://registry.npmjs.org/@acme%2finternal-utils
# PyPI: 404 from the JSON API means the project name is free
curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/acme-billing-sdk/json
```

### 6. Remediate npm with scope-to-registry pinning
Bind every internal scope to private registry so public package of same name can never be resolved.
```ini
# .npmrc (project root, committed)
@acme:registry=https://artifactory.example.com/api/npm/npm-internal/
//artifactory.example.com/api/npm/npm-internal/:_authToken=${NPM_TOKEN}
# Force the default registry to a single proxy that does NOT merge public + private
registry=https://artifactory.example.com/api/npm/npm-virtual/
```
Verify resolution source before installing:
```bash
npm config get @acme:registry
npm install --dry-run   # confirm @acme/* resolves from the private host
```

### 7. Remediate PyPI and Maven
Pin Python index resolution and Maven mirroring so public sources cannot shadow internal artifacts.
```toml
# pyproject.toml (PEP 621 / pip >= 23): explicit index pinning
[tool.pip]
index-url = "https://artifactory.example.com/api/pypi/pypi-internal/simple/"
# Do NOT use extra-index-url for internal packages — pip merges and picks highest version.
```
```xml
<!-- ~/.m2/settings.xml: mirror everything through a single virtual repo -->
<mirrors>
  <mirror>
    <id>internal-virtual</id>
    <mirrorOf>*</mirrorOf>
    <url>https://artifactory.example.com/artifactory/maven-virtual</url>
  </mirror>
</mirrors>
```

### 8. Defensively register placeholder packages
For names you cannot fully isolate, claim public name yourself with empty, non-functional placeholder so attacker cannot.
```bash
# npm placeholder claim (scoped, public)
mkdir acme-internal-utils && cd acme-internal-utils
npm init -y
npm pkg set version=0.0.1-placeholder description="Reserved internal name. Do not use."
npm publish --access public
```

### 9. Wire detection into CI
Fail pipeline if any new confusable dependency appears.
```yaml
# .github/workflows/depconfusion.yml
name: dependency-confusion
on: [push, pull_request]
jobs:
  confused:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go install github.com/visma-prodsec/confused@latest
      - name: Scan npm manifest
        run: $(go env GOPATH)/bin/confused -l npm -s '@acme/*' package.json
```

### 10. Run bundled helper for batch triage
Use included `agent.py` to scan tree and emit structured report combining `confused` and live registry probes.
```bash
python scripts/agent.py --path . --ecosystem npm \
  --secure-namespaces '@acme/*,@acme-internal/*' \
  --output report.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| confused | Detect lingering free namespaces for declared dependencies | https://github.com/visma-prodsec/confused |
| ConfusedDotnet | Same check for NuGet/.NET | https://github.com/visma-prodsec/ConfusedDotnet |
| OWASP dep-scan | Risk audit incl. `--private-ns` confusion check | https://github.com/owasp-dep-scan/dep-scan |
| OWASP CI/CD Top 10 | CICD-SEC-03 Dependency Chain Abuse | https://owasp.org/www-project-top-10-ci-cd-security-risks/ |
| Birsan research | Original dependency confusion writeup | https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 |
| npm scopes docs | Scope-to-registry pinning reference | https://docs.npmjs.com/cli/v10/using-npm/scope |

## Validation Criteria

- [ ] All dependency manifests in codebase enumerated.
- [ ] `confused` run for every relevant ecosystem with secure namespaces supplied.
- [ ] OWASP dep-scan `--private-ns` run and reconciled with `confused` output.
- [ ] Each flagged name confirmed claimable (404) or dismissed as false positive.
- [ ] Internal scopes pinned to private registry in `.npmrc` / `pip` config / Maven mirror.
- [ ] `extra-index-url` and merged virtual feeds reviewed for highest-version pull risk.
- [ ] Placeholder packages registered for names that cannot be isolated.
- [ ] CI job enforces check on every push/PR.
- [ ] Findings documented with owner and remediation status.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-dependency-confusion
