---
name: implementing-code-signing-for-artifacts
description: Implements code signing for build artifacts (binaries, packages, containers) using GPG, Sigstore, and platform-specific signing tools, establishing trust chains and verifying signatures in deployment pipelines.
subdomain: devsecops
facing: source
mitre_attack:
- T1195
- T1554
- T1059.004
- T1610
- T1611
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
upstream: implementing-code-signing-for-artifacts@54a7988 Apache-2.0, modified by wesh
---
Not for: encrypting artifacts (signing provides integrity, not confidentiality), for container image signing specifically (use cosign), or for source code authentication (use commit signing).

## Codegraph (do this first)
1. `codegraph_explore "crypto usage"` — locate cipher/sign/verify/hash/KDF call sites; `impact` before changing algorithm, mode or key handling. Output = read.
2. Fixing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- GPG key pair for traditional signing or Sigstore account for keyless signing
- Code signing certificate from Certificate Authority for public distribution
- CI/CD pipeline with access to signing keys or identity provider
- Verification infrastructure in deployment pipelines

## Workflow

### Step 1: Generate and Manage Signing Keys

```bash
# Generate GPG key for artifact signing
gpg --full-generate-key --batch <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: eddsa
Subkey-Curve: ed25519
Name-Real: CI Build System
Name-Email: ci-signing@company.com
Expire-Date: 1y
%no-protection
EOF
# Export public key for distribution
gpg --armor --export ci-signing@company.com > signing-key.pub
# Export private key for CI/CD (store in secrets manager)
gpg --armor --export-secret-keys ci-signing@company.com > signing-key.priv
```

### Step 2: Sign Build Artifacts in CI/CD

```yaml
# .github/workflows/build-sign.yml
name: Build and Sign
on:
  push:
    tags: ['v*']
jobs:
  build-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write  # For Sigstore keyless signing
    steps:
      - uses: actions/checkout@v4
      - name: Build artifacts
        run: |
          make build
          sha256sum dist/* > dist/checksums.sha256
      - name: Import GPG Key
        run: |
          echo "${{ secrets.GPG_PRIVATE_KEY }}" | gpg --batch --import
          gpg --list-secret-keys
      - name: Sign artifacts
        run: |
          for file in dist/*; do
            gpg --detach-sign --armor --local-user ci-signing@company.com "$file"
          done
      - name: Install cosign for keyless signing
        uses: sigstore/cosign-installer@v3
      - name: Keyless sign with Sigstore
        run: |
          for file in dist/*.tar.gz; do
            cosign sign-blob "$file" \
              --output-signature "${file}.sig" \
              --output-certificate "${file}.cert" \
              --yes
          done
      - name: Create Release with signed artifacts
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/*
            dist/*.asc
            dist/*.sig
            dist/*.cert
```

### Step 3: Verify Signatures in Deployment Pipeline

```bash
# Verify GPG signature
gpg --import signing-key.pub
gpg --verify artifact.tar.gz.asc artifact.tar.gz
# Verify Sigstore keyless signature
cosign verify-blob artifact.tar.gz \
  --signature artifact.tar.gz.sig \
  --certificate artifact.tar.gz.cert \
  --certificate-identity ci-signing@company.com \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verify checksums
sha256sum --check checksums.sha256
```

### Step 4: Sign npm Packages with Provenance

```json
{
  "scripts": {
    "prepublishOnly": "npm run build && npm run test"
  },
  "publishConfig": {
    "provenance": true
  }
}
```

```bash
# Publish npm package with provenance attestation
npm publish --provenance
```

## Key Concepts

| Term | Definition |
|------|------------|
| Code Signing | Cryptographic process of signing software artifacts to verify publisher identity and artifact integrity |
| Detached Signature | Signature stored in separate file from artifact, allowing independent distribution |
| Keyless Signing | Sigstore's approach using short-lived certificates tied to OIDC identities instead of long-lived keys |
| Provenance | Metadata describing how, where, and by whom artifact was built |
| Transparency Log | Append-only log (Rekor) that records all signing events for public auditability |
| Trust Chain | Hierarchical chain from root CA to signing certificate establishing trust in signer's identity |
| SLSA | Supply-chain Levels for Software Artifacts — framework defining levels of supply chain security |

## Tools & Systems

- **GPG/PGP**: Traditional asymmetric cryptography tool for signing and verifying artifacts
- **Sigstore (cosign)**: Modern keyless signing infrastructure using OIDC identity and transparency logs
- **Rekor**: Sigstore's transparency log recording all signing events immutably
- **Fulcio**: Sigstore's certificate authority issuing short-lived certificates bound to OIDC identities
- **notation**: Microsoft's artifact signing tool for OCI registries (Project Notary v2)

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-code-signing-for-artifacts
