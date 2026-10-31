---
name: implementing-sigstore-for-software-signing
description: Implements Sigstore-based software signing and verification using Cosign keyless signing, Rekor transparency log verification, and Fulcio certificate authority integration to establish cryptographic provenance for container images, binaries, and software artifacts, including OIDC-based identity binding and CI/CD pipeline integration.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1610
- T1611
nist_csf:
- GV.SC-01
- GV.SC-03
- GV.SC-06
- GV.SC-07
upstream: implementing-sigstore-for-software-signing@54a7988 Apache-2.0, modified by wesh
---
Not for: signing artifacts that require air-gapped or offline signing workflows where OIDC authentication is unavailable, for environments that cannot reach the public Sigstore infrastructure (Fulcio, Rekor) and have no private instance deployed, or as a replacement for traditional PGP/GPG signing where regulatory compliance mandates specific key management procedures.

## Prerequisites

- Cosign CLI v2.4+ installed (`go install github.com/sigstore/cosign/v2/cmd/cosign@latest` or binary release)
- Access to OIDC identity provider supported by Fulcio (Google, GitHub, Microsoft, or custom OIDC issuer)
- Container registry credentials (for signing container images) with push access to store signature objects
- Python 3.9+ with `sigstore`, `requests`, and `cryptography` packages for automation agent
- Network access to `fulcio.sigstore.dev`, `rekor.sigstore.dev`, and `tuf-repo-cdn.sigstore.dev` (or private Sigstore instance URLs)

## Workflow

### Step 1: Install and Configure Cosign

Install Cosign and verify it can reach Sigstore infrastructure:

- **Install from binary release**: Download appropriate binary from Cosign GitHub releases page and verify its checksum. On Linux: `curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x cosign-linux-amd64 && sudo mv cosign-linux-amd64 /usr/local/bin/cosign`
- **Verify installation**: Run `cosign version` to confirm version and check connectivity to Sigstore services with `cosign initialize` which fetches TUF root of trust
- **Configure custom infrastructure** (optional): If running private Sigstore stack, set `--fulcio-url`, `--rekor-url`, and `--oidc-issuer` flags or use environment variables `COSIGN_REKOR_URL` and `COSIGN_FULCIO_URL`

### Step 2: Keyless Signing with Cosign and Fulcio

Perform identity-based signing where Fulcio issues short-lived certificate bound to your OIDC identity:

- **Sign container image**: Run `cosign sign <IMAGE_DIGEST>` which triggers OIDC authentication flow. Cosign generates ephemeral key pair, obtains short-lived certificate from Fulcio binding public key to OIDC identity, signs image digest, and records signing event in Rekor. private key is destroyed immediately after signing.
- **Sign blob (file)**: Run `cosign sign-blob <file> --bundle artifact.sigstore.json` to sign arbitrary files. bundle contains signature, certificate, timestamp, and Rekor inclusion proof.
- **Non-interactive signing in CI**: Set `SIGSTORE_ID_TOKEN` environment variable with valid OIDC token (e.g., from GitHub Actions OIDC or GCP workload identity) to skip browser-based authentication flow:
  ```bash
  export SIGSTORE_ID_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -r '.value')
  cosign sign $IMAGE_DIGEST
  ```
- **Supported OIDC providers**: Google (`https://accounts.google.com`), GitHub (`https://github.com/login/oauth`), Microsoft (`https://login.microsoftonline.com`), GitLab (`https://gitlab.com`), and custom providers registered with private Fulcio instance

### Step 3: Verify Signed Artifacts

Verify that artifacts were signed by expected identities from expected OIDC issuers:

- **Verify container image**: Run `cosign verify <IMAGE_URI> --certificate-identity=name@example.com --certificate-oidc-issuer=https://accounts.google.com` to confirm image was signed by specified identity. Cosign validates certificate chain, checks Rekor inclusion proof, and verifies signature matches current image digest.
- **Verify signed blob**: Run `cosign verify-blob <file> --bundle artifact.sigstore.json --certificate-identity=name@example.com --certificate-oidc-issuer=https://accounts.google.com`
- **Regex matching for CI identities**: Use `--certificate-identity-regexp` to match CI workflow identities:
  ```bash
  cosign verify $IMAGE --certificate-identity-regexp="https://github.com/myorg/myrepo/.*" \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
  ```
- **Verification failure modes**: Cosign returns non-zero exit code on failure. Common failures include certificate identity mismatch, expired certificates without valid Rekor timestamp, missing Rekor entry, and image digest mismatch (image was modified after signing).

### Step 4: Query Rekor Transparency Log

Search and verify entries in Rekor transparency log to audit signing events:

- **Search by email identity**: Use `rekor-cli search --email user@example.com` to find all signing events for identity
- **Search by artifact hash**: Use `rekor-cli search --sha sha256:<hash>` to find signing events for specific artifact
- **Retrieve and verify entry**: Use `rekor-cli get --uuid <entry_uuid>` to retrieve full entry details including certificate, signature, and artifact hash
- **Verify log inclusion**: Use `rekor-cli verify --entry-uuid <uuid>` to verify entry's inclusion proof against signed tree head, confirming entry exists in append-only log and has not been tampered with
- **REST API queries**: Query `https://rekor.sigstore.dev/api/v1/index/retrieve` with POST body `{"hash": "sha256:<hash>"}` to retrieve entry UUIDs, then fetch full entries from `/api/v1/log/entries/<uuid>`
- **Monitor for consistency**: Use rekor-monitor tool or Omniwitness to continuously verify log remains append-only and entries are never mutated or removed

### Step 5: Integrate into CI/CD Pipelines

Embed signing and verification into build and deployment pipelines:

- **GitHub Actions**: Use `sigstore/cosign-installer` action to install Cosign, then sign images using GitHub OIDC token as identity. signing identity will be workflow URL (e.g., `https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main`).
- **Kubernetes admission enforcement**: Deploy Sigstore Policy Controller or Kyverno with Cosign verification policies to reject unsigned or incorrectly signed images at admission time
- **Supply chain metadata**: Use `cosign attest` to attach in-toto attestations (SLSA provenance, SBOM, vulnerability scan results) to images, signed with same keyless flow, enabling consumers to verify both artifact and its build metadata

## Key Concepts

| Term | Definition |
|------|------------|
| **Keyless Signing** | Identity-based signing that uses short-lived certificates from Fulcio bound to OIDC identities instead of long-lived cryptographic keys, eliminating key management overhead |
| **Fulcio** | Sigstore's certificate authority that issues short-lived X.509 certificates after verifying OIDC tokens, binding ephemeral public key to verified identity |
| **Rekor** | Sigstore's immutable, append-only transparency log that records signing events with timestamps, enabling auditors to verify when and by whom artifact was signed |
| **Cosign** | primary CLI tool for signing and verifying container images and blobs using Sigstore infrastructure (Fulcio + Rekor) |
| **TUF Root of Trust** | Update Framework distribution mechanism for Sigstore's root CA certificate and Rekor public key, ensuring clients trust correct Sigstore infrastructure |
| **OIDC Identity Binding** | process where Fulcio verifies user's identity through OpenID Connect token and binds it to short-lived signing certificate |
| **Inclusion Proof** | cryptographic proof from Rekor demonstrating that signing event entry exists within transparency log's Merkle tree |

## Tools & Systems

- **Cosign**: CLI tool for signing containers and blobs, verifying signatures, and attaching attestations using Sigstore keyless signing or traditional key-based signing
- **Fulcio**: Free root certificate authority for code signing certificates issued based on OIDC identity verification with validity period of approximately 10 minutes
- **Rekor**: Transparency log server providing tamper-evident storage of signing metadata, searchable by identity, artifact hash, or public key
- **Sigstore Policy Controller**: Kubernetes admission webhook that enforces image signing policies by verifying Cosign signatures and attestations before allowing pod creation
- **rekor-cli**: Command-line client for querying, uploading, and verifying entries in Rekor transparency log

## Sigstore Signing Verification Report

**Artifact**: ghcr.io/myorg/myapp@sha256:a1b2c3d4...
**Verification Status**: PASSED

**Certificate Details**:
  Subject: https://github.com/myorg/myapp/.github/workflows/build.yml@refs/heads/main
  Issuer: https://token.actions.githubusercontent.com
  Valid From: 2026-03-19T10:00:00Z
  Valid To: 2026-03-19T10:10:00Z

**Rekor Entry**:
  UUID: 24296fb24b8ad77a8d52...
  Log Index: 89234567
  Integrated Time: 2026-03-19T10:00:05Z
  Inclusion Proof: VERIFIED (tree size: 92000000, root hash: e4f5a6...)

**Policy Check**: Image signed by authorized CI workflow identity
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-sigstore-for-software-signing
