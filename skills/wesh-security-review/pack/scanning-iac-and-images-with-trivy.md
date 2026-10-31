---
name: scanning-iac-and-images-with-trivy
description: Scans container images, Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm), filesystems, git repos, and SBOMs with Trivy's vuln, misconfig, secret, and license scanners.
subdomain: devsecops
facing: config
mitre_attack:
- T1525
nist_csf:
- ID.RA-01
upstream: scanning-iac-and-images-with-trivy@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- A Linux/macOS/Windows host or CI runner with network access to download Trivy vulnerability database.
- Docker (optional) if scanning local images by name or using containerized Trivy.
- Install Trivy (Aqua Security official methods):

```bash
# Debian/Ubuntu (APT repository)
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
# RHEL/CentOS (YUM repository), macOS (Homebrew), and install script
brew install trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
# Containerized usage (no install)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image python:3.10-alpine
# Verify
trivy --version
```

- For air-gapped or rate-limited environments, pre-download DB with `trivy image --download-db-only` and Java/policy bundles as needed.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1525 | Implant Internal Image | Persistence | Trivy detects vulnerable or malicious images/layers and embedded secrets before they are implanted in registry and propagated to running workloads. |

## Workflow

### 1. Scan container image for vulnerabilities

Run vulnerability-only scan of registry image, restricting to high/critical findings and ignoring CVEs with no available fix:

```bash
trivy image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --format table \
  python:3.10-alpine
```

Scan image saved as tarball (useful when image is built but not yet pushed):

```bash
docker save myorg/app:1.4.0 -o app.tar
trivy image --input app.tar --severity CRITICAL --format json --output app-vulns.json
```

### 2. Enable multiple scanners on image

Run vulnerability, misconfiguration, secret, and license scanners together:

```bash
trivy image \
  --scanners vuln,misconfig,secret,license \
  --severity MEDIUM,HIGH,CRITICAL \
  myorg/app:1.4.0
```

Scan image's embedded config (Dockerfile-equivalent build history and history secrets):

```bash
trivy image --image-config-scanners misconfig,secret myorg/app:1.4.0
```

### 3. Scan Infrastructure-as-Code (misconfiguration)

Scan directory of Terraform / Kubernetes / Dockerfile / Helm / CloudFormation for misconfigurations using the `config` target:

```bash
# Scan a Terraform / IaC directory
trivy config \
  --severity HIGH,CRITICAL \
  --format table \
  ./infra
# Scan with custom Rego policies and a specific policy namespace
trivy config \
  --config-policy ./policies \
  --policy-namespaces user \
  ./infra
```

Alternatively use the `fs` (filesystem) target with misconfig scanner explicitly:

```bash
trivy fs --scanners misconfig,secret --severity HIGH,CRITICAL ./infra
```

### 4. Scan repository and detect secrets

Scan local working tree (or remote repo) for vulnerabilities in lockfiles and hard-coded secrets:

```bash
# Local filesystem (dependencies + secrets)
trivy fs --scanners vuln,secret --severity HIGH,CRITICAL .
# Remote Git repository
trivy repository --scanners vuln,secret https://github.com/myorg/myrepo
```

### 5. Generate and re-scan SBOM

Produce CycloneDX SBOM from image, then scan SBOM itself for vulnerabilities (so stored SBOM can be re-evaluated as new CVEs are disclosed):

```bash
# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom.cdx.json myorg/app:1.4.0
# Generate SPDX SBOM
trivy image --format spdx-json --output sbom.spdx.json myorg/app:1.4.0
# Re-scan the SBOM for vulnerabilities later
trivy sbom --severity HIGH,CRITICAL sbom.cdx.json
```

### 6. Emit SARIF for code-scanning dashboards

Produce SARIF for GitHub Advanced Security / code scanning ingestion:

```bash
trivy image \
  --format sarif \
  --output trivy-results.sarif \
  --severity HIGH,CRITICAL \
  myorg/app:1.4.0
```

### 7. Gate CI/CD pipeline with exit codes

Use `--exit-code 1` so pipeline step fails when findings at or above chosen severity are present. Separate "report everything" run (exit 0) from "enforce" run (exit 1):

```bash
# 1) Informational report (never fails the build)
trivy image --severity LOW,MEDIUM,HIGH,CRITICAL --exit-code 0 --format table myorg/app:1.4.0
# 2) Enforcement gate (fails build on HIGH/CRITICAL with a fix available)
trivy image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  --format json --output gate.json \
  myorg/app:1.4.0
```

Example GitHub Actions step using official action:

```yaml
- name: Run Trivy image scan (gate)
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myorg/app:1.4.0'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'HIGH,CRITICAL'
    ignore-unfixed: true
    exit-code: '1'
```

### 8. Manage false positives and DB

Suppress accepted-risk findings with a `.trivyignore` file and keep DB current:

```bash
# .trivyignore — one CVE/AVD/secret rule ID per line
echo "CVE-2023-12345" >> .trivyignore
echo "AVD-AWS-0089"   >> .trivyignore
# Refresh DBs explicitly (useful for caching layers in CI)
trivy image --download-db-only
trivy image --download-java-db-only
# Scan a Kubernetes cluster (summary report)
trivy k8s --report summary --severity HIGH,CRITICAL cluster
```

## Tools and Resources

| Tool / Resource | Purpose | Link |
|------------------|---------|------|
| Trivy | Core scanner CLI | https://github.com/aquasecurity/trivy |
| Trivy Documentation | Official docs (targets, scanners, flags) | https://trivy.dev/latest/docs/ |
| trivy-action | GitHub Actions integration | https://github.com/aquasecurity/trivy-action |
| Trivy Operator | In-cluster Kubernetes continuous scanning | https://github.com/aquasecurity/trivy-operator |
| Trivy vulnerability DB | OSS vulnerability data source | https://github.com/aquasecurity/trivy-db |
| CycloneDX | SBOM standard emitted by Trivy | https://cyclonedx.org/ |

## Validation Criteria

- [ ] Trivy installed and `trivy --version` reports valid version.
- [ ] Container image scanned for vulnerabilities with severity filtering applied.
- [ ] Image scanned with multiple scanners (vuln, misconfig, secret, license).
- [ ] IaC directory scanned with `trivy config` and misconfigurations reviewed.
- [ ] Secret scanning run against repository.
- [ ] CycloneDX/SPDX SBOM generated and successfully re-scanned with `trivy sbom`.
- [ ] SARIF output produced for code-scanning dashboard.
- [ ] CI/CD gate fails build on HIGH/CRITICAL findings via `--exit-code 1`.
- [ ] `.trivyignore` configured for accepted-risk findings with documented justification.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/scanning-iac-and-images-with-trivy
