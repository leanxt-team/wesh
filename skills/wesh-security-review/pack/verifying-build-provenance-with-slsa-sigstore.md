---
name: verifying-build-provenance-with-slsa-sigstore
description: Verifies artifact signatures and SLSA provenance using Sigstore's cosign (verify, verify-attestation, verify-blob-attestation) and slsa-verifier (verify-artifact), enforcing keyless OIDC builder identity and source repo against SLSA Build levels.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195
nist_csf:
- PR.DS-01
upstream: verifying-build-provenance-with-slsa-sigstore@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- **cosign** (Sigstore CLI):
  ```bash
  go install github.com/sigstore/cosign/v2/cmd/cosign@latest
  # or download a release binary from https://github.com/sigstore/cosign/releases
  ```
- **slsa-verifier**:
  ```bash
  go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
  # or:
  curl -sSL https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64 \
    -o /usr/local/bin/slsa-verifier && chmod +x /usr/local/bin/slsa-verifier
  ```
- Network access to Rekor (`https://rekor.sigstore.dev`) and Fulcio for transparency-log verification.
- Artifact plus its provenance/attestation bundle (`.sigstore`, `.intoto.jsonl`, or attached OCI attestation).

## MITRE ATT&CK Mapping

| ID | Tactic | Technique Name | Relevance |
|----|--------|----------------|-----------|
| T1195 | Initial Access | Supply Chain Compromise | Verifying provenance and signatures detects artifacts that were tampered with or substituted in build/distribution chain, preventing supply-chain compromise from reaching deployment. |

## Workflow

### Step 1: Verify keyless cosign signature on image
Pin both OIDC issuer and certificate identity (exact workflow that signed). bare `cosign verify` without identity pinning is meaningless — anyone can sign.

```bash
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/.github/workflows/.*@refs/tags/v.*" \
  ghcr.io/myorg/myrepo:v1.2.3
```
Non-zero exit or empty result means verification failed — do not deploy.

### Step 2: Verify SLSA provenance attestation on image
Signature proves *who* signed; provenance attestation proves *how it was built*. Verify in-toto SLSA predicate type.

```bash
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build-sign.yml@refs/heads/main" \
  ghcr.io/myorg/myrepo:v1.2.3
```
Supported predicate types include `slsaprovenance`, `slsaprovenance02`, and `slsaprovenance1`.

### Step 3: Inspect provenance predicate
Decode verified attestation to confirm source repo, commit, and builder match expectations.

```bash
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp '.*' \
  ghcr.io/myorg/myrepo:v1.2.3 \
  | jq -r '.payload' | base64 -d | jq '.predicate.buildDefinition.externalParameters, .predicate.runDetails.builder.id'
```

### Step 4: Verify release binary with slsa-verifier
For downloadable binaries (e.g., produced by `slsa-github-generator`), pin source URI and tag. slsa-verifier checks cryptographic signature on provenance and that expected builder produced it.

```bash
slsa-verifier verify-artifact slsa-test-linux-amd64 \
  --provenance-path slsa-test-linux-amd64.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.2.3
# Optionally pin the builder identity (SLSA L3)
slsa-verifier verify-artifact ./mybin \
  --provenance-path ./mybin.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0
```

### Step 5: Verify GitHub artifact attestations / blob bundles
For artifacts signed via `actions/attest-build-provenance`, bundle uses new Sigstore bundle format.

```bash
cosign verify-blob-attestation \
  --bundle ./myartifact.sigstore.json \
  --new-bundle-format \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/myorg/myrepo/" \
  ./myartifact
# Equivalent native GitHub CLI verification
gh attestation verify ./myartifact --repo myorg/myrepo
```

### Step 6: Enforce verification as gate
Wrap verification so pipeline fails closed on any error.

```bash
#!/usr/bin/env bash
set -euo pipefail
IMG="ghcr.io/myorg/myrepo:v1.2.3"
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/" "$IMG" >/dev/null
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/" "$IMG" >/dev/null
echo "[+] $IMG verified: signature + SLSA provenance OK"
```

### Step 7: Map findings to SLSA Build levels
Document level each consumed artifact achieves:
- **Build L1** — provenance exists (build process generates it), but it may be unsigned/forgeable.
- **Build L2** — provenance is signed by hosted build service.
- **Build L3** — provenance is non-forgeable: generated on isolated, hardened builder where secrets are unavailable to user-defined steps (e.g., `slsa-github-generator` reusable workflows). Require L3 for high-trust artifacts.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| cosign | Sign/verify artifacts and attestations (keyless) | https://github.com/sigstore/cosign |
| slsa-verifier | Verify SLSA provenance from compliant builders | https://github.com/slsa-framework/slsa-verifier |
| slsa-github-generator | Produce SLSA L3 provenance in GitHub Actions | https://github.com/slsa-framework/slsa-github-generator |
| actions/attest-build-provenance | GitHub-native provenance attestation | https://github.com/actions/attest-build-provenance |
| SLSA specification | Build levels and provenance schema | https://slsa.dev/spec/v1.0/ |
| Sigstore docs | Fulcio, Rekor, cosign verification | https://docs.sigstore.dev/cosign/verifying/verify/ |

## Verification Identity Reference

| Field | Where it comes from | Why it matters |
|-------|--------------------|----------------|
| `--certificate-oidc-issuer` | OIDC issuer (e.g., GitHub Actions) | Restricts who could have requested signing cert |
| `--certificate-identity[-regexp]` | exact/patterned workflow identity (SAN) | Restricts which workflow signed; prevents impersonation |
| `--source-uri` (slsa-verifier) | Expected source repo | Confirms artifact came from your repo |
| `--source-tag` / `--source-versioned-tag` | Expected git tag | Prevents rollback/substitution |
| `--builder-id` | Trusted builder workflow ref | Enforces SLSA L3 non-forgeable builder |

## Validation Criteria

- [ ] cosign and slsa-verifier installed and report versions
- [ ] Image signature verified with pinned OIDC issuer AND certificate identity
- [ ] SLSA provenance attestation verified (`--type slsaprovenance`)
- [ ] Provenance predicate inspected; source repo/commit/builder match
- [ ] Release binary verified with slsa-verifier (source-uri + tag pinned)
- [ ] GitHub blob/bundle attestation verified
- [ ] Verification wired as fail-closed CI/admission gate
- [ ] Each consumed artifact assigned SLSA Build level

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/verifying-build-provenance-with-slsa-sigstore
