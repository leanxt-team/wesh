---
name: securing-container-registry-images
description: Secures container registry images (ECR, ACR, GCR, Docker Hub) by scanning with Trivy and Grype, signing with Cosign and Sigstore, configuring registry access controls, and building CI/CD pipelines that block unscanned or unsigned images.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1610
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: securing-container-registry-images@54a7988 Apache-2.0, modified by wesh
---
Not for: runtime container security (use Falco or Sysdig), for Kubernetes admission control (use OPA Gatekeeper or Kyverno after establishing registry controls), or for host-level vulnerability scanning (use Amazon Inspector or Qualys).

## Prerequisites

- Trivy installed (`brew install trivy` or `apt install trivy`)
- Grype installed (`curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh`)
- Cosign installed for image signing (`go install github.com/sigstore/cosign/v2/cmd/cosign@latest`)
- Syft installed for SBOM generation (`curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`)
- Container registry access (ECR, ACR, GCR, or private registry)

## Workflow

### Step 1: Scan Images for Vulnerabilities with Trivy

Run comprehensive vulnerability scans against container images before and after pushing to registry.

```bash
# Scan a local image for vulnerabilities
trivy image --severity HIGH,CRITICAL myapp:latest
# Scan a remote registry image
trivy image --severity HIGH,CRITICAL 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Scan with JSON output for CI/CD processing
trivy image --format json --output trivy-results.json myapp:latest
# Scan for vulnerabilities AND misconfigurations
trivy image --scanners vuln,misconfig,secret myapp:latest
# Scan a specific image with SBOM output
trivy image --format spdx-json --output sbom.json myapp:latest
# Fail CI/CD if critical vulnerabilities found
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

### Step 2: Scan with Grype for Additional Coverage

Use Grype as complementary scanner for broader vulnerability database coverage.

```bash
# Scan image with Grype
grype myapp:latest
# Scan with severity threshold
grype myapp:latest --fail-on critical
# Output in JSON for processing
grype myapp:latest -o json > grype-results.json
# Scan an SBOM instead of the image directly
syft myapp:latest -o spdx-json > sbom.json
grype sbom:sbom.json
# Scan a directory-based image export
grype dir:/path/to/image-rootfs
```

### Step 3: Generate Software Bill of Materials (SBOM)

Create SBOMs for all images to maintain inventory of software components and dependencies.

```bash
# Generate SBOM with Syft in SPDX format
syft myapp:latest -o spdx-json > sbom-spdx.json
# Generate SBOM in CycloneDX format
syft myapp:latest -o cyclonedx-json > sbom-cyclonedx.json
# Attach SBOM to the image as an OCI artifact
cosign attach sbom --sbom sbom-spdx.json \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Verify SBOM contents
syft myapp:latest -o table | head -50
```

### Step 4: Sign Images with Cosign and Sigstore

Implement image signing to ensure image integrity and authenticity in supply chain.

```bash
# Generate a key pair for signing
cosign generate-key-pair
# Sign an image in the registry
cosign sign --key cosign.key \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Sign using keyless signing with Sigstore (OIDC-based)
cosign sign --yes \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Verify image signature
cosign verify --key cosign.pub \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Verify keyless signature
cosign verify \
  --certificate-identity developer@company.com \
  --certificate-oidc-issuer https://accounts.google.com \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
# Add attestation with scan results
cosign attest --predicate trivy-results.json \
  --key cosign.key \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

### Step 5: Configure Registry-Level Security Controls

Set up registry-specific security features for ECR, ACR, and GCR.

```bash
# AWS ECR: Enable image scanning on push
aws ecr put-image-scanning-configuration \
  --repository-name myapp \
  --image-scanning-configuration scanOnPush=true
# ECR: Set image tag immutability (prevent tag overwrites)
aws ecr put-image-tag-mutability \
  --repository-name myapp \
  --image-tag-mutability IMMUTABLE
# ECR: Set lifecycle policy to clean up untagged images
aws ecr put-lifecycle-policy \
  --repository-name myapp \
  --lifecycle-policy-text '{
    "rules": [{
      "rulePriority": 1,
      "description": "Remove untagged images after 7 days",
      "selection": {"tagStatus": "untagged", "countType": "sinceImagePushed", "countUnit": "days", "countNumber": 7},
      "action": {"type": "expire"}
    }]
  }'
# ECR: Get scan findings for an image
aws ecr describe-image-scan-findings \
  --repository-name myapp \
  --image-id imageTag=latest \
  --query 'imageScanFindings.findingSeverityCounts'
# Azure ACR: Enable Defender for container registries
az security pricing create --name ContainerRegistry --tier standard
# GCR: Enable Container Analysis
gcloud services enable containeranalysis.googleapis.com
gcloud artifacts docker images list-vulnerabilities \
  LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:DIGEST
```

### Step 6: Build CI/CD Pipeline with Security Gates

Integrate scanning and signing into CI/CD pipeline as mandatory gates.

```yaml
# GitHub Actions: Scan, sign, and push image
name: Container Security Pipeline
on: push
jobs:
  build-scan-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: json
          output: trivy-results.json
          severity: CRITICAL,HIGH
          exit-code: 1
      - name: Generate SBOM
        run: syft myapp:${{ github.sha }} -o spdx-json > sbom.json
      - name: Push to ECR
        run: |
          aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker tag myapp:${{ github.sha }} $ECR_REGISTRY/myapp:${{ github.sha }}
          docker push $ECR_REGISTRY/myapp:${{ github.sha }}
      - name: Sign image with Cosign
        run: |
          cosign sign --key env://COSIGN_PRIVATE_KEY \
            $ECR_REGISTRY/myapp:${{ github.sha }}
      - name: Attach SBOM
        run: |
          cosign attach sbom --sbom sbom.json \
            $ECR_REGISTRY/myapp:${{ github.sha }}
```

## Key Concepts

| Term | Definition |
|------|------------|
| Container Image Scanning | Automated analysis of container image layers to identify known vulnerabilities in OS packages and application dependencies |
| Image Signing | Cryptographic attestation that verifies authenticity and integrity of container image using Cosign or Notation |
| SBOM | Software Bill of Materials, comprehensive inventory of software components, libraries, and dependencies in container image |
| Tag Immutability | Registry setting that prevents overwriting existing image tags, ensuring that tag always refers to same image digest |
| Sigstore | Open-source project providing keyless signing, transparency logs, and verification tooling for software supply chain security |
| Image Attestation | Cryptographically signed metadata attached to image (scan results, SBOM, build provenance) that can be verified before deployment |

## Tools & Systems

- **Trivy**: Comprehensive vulnerability scanner for container images, filesystems, git repos, and Kubernetes resources
- **Grype**: Anchore's vulnerability scanner with broad vulnerability database coverage for container images and SBOMs
- **Cosign**: Sigstore tool for signing, verifying, and attesting container images with key-based or keyless workflows
- **Syft**: SBOM generation tool supporting SPDX and CycloneDX formats for container images and filesystems
- **AWS ECR**: Container registry with built-in scanning, tag immutability, and lifecycle policies

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/securing-container-registry-images
