---
name: generating-and-analyzing-sboms
description: Generate CycloneDX and SPDX SBOMs from container images and filesystems with Syft, correlate them to CVEs with Grype, and sign/attest them with Cosign.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195.001
nist_csf:
- ID.AM-08
upstream: generating-and-analyzing-sboms@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** Generate and scan SBOMs only for software and images you own or are authorized to assess. Treat SBOMs as sensitive inventory data — they reveal your dependency attack surface.

## Prerequisites

- Install Syft and Grype (official install scripts):
  ```bash
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  ```
- Install Cosign for signing/attestation:
  ```bash
  # via Go, or download a release from https://github.com/sigstore/cosign/releases
  go install github.com/sigstore/cosign/v2/cmd/cosign@latest
  ```
- Access to target images/source and (for signing) registry plus keys or keyless OIDC.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | SBOM generation and vulnerability correlation expose compromised or vulnerable dependencies — attack surface adversaries abuse under this technique. |

This is defensive supply-chain skill; mapping reflects adversary technique it is designed to detect and mitigate.

## Workflow

### 1. Generate CycloneDX SBOM from container image
`-o <format>` selects output; `cyclonedx-json` is security-oriented.
```bash
syft alpine:latest -o cyclonedx-json=alpine.cdx.json
```

### 2. Generate SPDX SBOM from source directory
Use the `dir:` source to inventory checked-out repository; `spdx-json` for SPDX standard.
```bash
syft dir:. -o spdx-json=app.spdx.json
```

### 3. Emit multiple formats at once
Produce both standards in single pass for different consumers.
```bash
syft myorg/app:1.4.2 \
  -o cyclonedx-json=app.cdx.json \
  -o spdx-json=app.spdx.json \
  -o table
```

### 4. Scan SBOM for vulnerabilities with Grype
Decoupling generation from scanning lets you re-scan stored SBOMs as new CVEs land — without rebuilding.
```bash
# Scan an existing SBOM
grype sbom:app.cdx.json -o table
# JSON report for automation
grype sbom:app.cdx.json -o json > app.vulns.json
```
You can also scan image directly (Grype generates SBOM internally):
```bash
grype myorg/app:1.4.2 -o table
```

### 5. Gate CI/CD on severity
`--fail-on` exits non-zero at or above severity, failing pipeline.
```bash
grype sbom:app.cdx.json --fail-on high
```
Filter out unfixable noise with a `.grype.yaml` policy (`only-fixed: true`) or `--only-fixed`:
```bash
grype sbom:app.cdx.json --only-fixed --fail-on critical
```

### 6. Sign and attach SBOM as attestation
Cosign records SBOM as signed, in-toto attestation alongside image in registry.
```bash
# Key-based signing
cosign attest --key cosign.key \
  --predicate app.spdx.json \
  --type spdxjson \
  myorg/app:1.4.2
# Keyless (Sigstore OIDC / Fulcio + Rekor)
COSIGN_EXPERIMENTAL=1 cosign attest \
  --predicate app.cdx.json \
  --type cyclonedx \
  myorg/app:1.4.2
```

### 7. Verify attestation downstream
Consumers verify provenance before trusting image.
```bash
cosign verify-attestation --key cosign.pub --type spdxjson myorg/app:1.4.2
```

### 8. Retrieve and re-scan attached SBOMs
Pull attested SBOM from registry and re-run Grype as part of continuous monitoring.
```bash
cosign download attestation myorg/app:1.4.2 \
  | jq -r '.payload' | base64 -d | jq '.predicate' > pulled.spdx.json
grype sbom:pulled.spdx.json -o table
```

### 9. Correlate to vulnerability intelligence
Feed Grype JSON into your vulnerability management workflow: deduplicate by CVE, enrich with EPSS/KEV for prioritization, and track remediation SLAs. Re-scan stored SBOMs on each Grype DB update to catch newly disclosed CVEs in unchanged artifacts.

## Tools and Resources

| Tool | Purpose | Link |
|------|---------|------|
| Syft | SBOM generation | https://github.com/anchore/syft |
| Grype | Vulnerability scanning of SBOMs/images | https://github.com/anchore/grype |
| Cosign | SBOM signing/attestation | https://github.com/sigstore/cosign |
| CycloneDX | Security-focused SBOM standard | https://cyclonedx.org/ |
| SPDX | ISO SBOM standard | https://spdx.dev/ |
| CISA SBOM | Guidance and minimum elements | https://www.cisa.gov/sbom |

## Format Comparison

| Aspect | CycloneDX | SPDX |
|--------|-----------|------|
| Steward | OWASP | Linux Foundation / ISO 5962 |
| Strength | Security, VEX, vulnerabilities | Licensing, provenance |
| Common syft `-o` values | `cyclonedx-json`, `cyclonedx-xml` | `spdx-json`, `spdx` (tag-value) |

## Validation Criteria

- [ ] CycloneDX SBOM generated from target image
- [ ] SPDX SBOM generated from source where required
- [ ] SBOM scanned with Grype producing CVE report
- [ ] CI/CD gated with `--fail-on` at agreed severity
- [ ] SBOM signed and attached as attestation with Cosign
- [ ] Attestation verified downstream
- [ ] Stored SBOMs re-scanned on Grype DB updates
- [ ] Findings correlated/prioritized (EPSS/KEV) and tracked to remediation

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/generating-and-analyzing-sboms
