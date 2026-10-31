---
name: performing-container-security-scanning-with-trivy
description: Runs Trivy across every target type it supports - container images, filesystems, Git repositories, and Kubernetes clusters - for OS and dependency vulnerabilities, IaC misconfiguration, exposed secrets, and licences, generating CycloneDX or SPDX SBOMs.
subdomain: container-security
facing: config
mitre_attack:
- T1610
- T1611
- T1609
- T1525
- T1195
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
upstream: performing-container-security-scanning-with-trivy@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Trivy v0.50+ installed (binary, Docker, or Homebrew)
- Docker daemon access for local image scanning
- Container registry credentials for remote image scanning
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins) for pipeline integration
- Kubernetes cluster for Trivy Operator deployment (optional)

## Steps

### Step 1: Scan Container Images

Run vulnerability and secret scanning against container images from local builds or remote registries. Configure severity thresholds and ignore unfixed vulnerabilities.

### Step 2: Generate SBOM

Produce CycloneDX or SPDX SBOM documents from scanned images for supply chain compliance and vulnerability tracking across software lifecycle.

### Step 3: Scan IaC and Kubernetes Manifests

Detect misconfigurations in Dockerfiles, Kubernetes YAML, Terraform, and Helm charts using built-in policy checks aligned with CIS benchmarks.

### Step 4: Integrate into CI/CD

Add Trivy scanning as pipeline gate that blocks builds with critical/high vulnerabilities, generates SARIF reports for GitHub Advanced Security, and produces JUnit XML for test dashboards.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-container-security-scanning-with-trivy
