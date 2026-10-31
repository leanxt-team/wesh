---
name: migrating-to-post-quantum-cryptography
description: Build a cryptographic inventory/CBOM with OpenSSL 3.5+, deploy hybrid post-quantum key exchange (X25519MLKEM768) on TLS/VPN/SSH endpoints, generate ML-KEM/ML-DSA keys and PQC/hybrid certificates, and prioritize migration by harvest-now-decrypt-later (HNDL) exposure per NIST SP 1800-38.
subdomain: cryptography
facing: source
mitre_attack:
- T1573
nist_csf:
- PR.DS-02
upstream: migrating-to-post-quantum-cryptography@54a7988 Apache-2.0, modified by wesh
---
## Codegraph (do this first)
1. `codegraph_explore "crypto usage"` — locate cipher/sign/verify/hash/KDF call sites; `impact` before changing algorithm, mode or key handling. Output = read.
2. Fixing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

> **Scope and Authorization:** This skill describes defensive cryptographic-migration engineering on systems you own or operate. Cryptographic discovery scanning can touch sensitive key material and production traffic — run inventory tooling only with authorization and in line with your organization's change-management and data-handling policies.

## Prerequisites

- OpenSSL **3.5.0 or later**, which ships native ML-KEM, ML-DSA, and SLH-DSA support:
  ```bash
  openssl version            # expect 3.5.0+
  openssl list -kem-algorithms | grep -i mlkem
  openssl list -signature-algorithms | grep -i mldsa
  ```
- For OpenSSL 3.0–3.4, Open Quantum Safe **oqs-provider** plus **liboqs**:
  ```bash
  git clone https://github.com/open-quantum-safe/liboqs && \
    cmake -S liboqs -B liboqs/build && cmake --build liboqs/build && \
    sudo cmake --install liboqs/build
  git clone https://github.com/open-quantum-safe/oqs-provider && \
    cmake -S oqs-provider -B oqs-provider/_build && \
    cmake --build oqs-provider/_build && \
    sudo cmake --install oqs-provider/_build
  ```
- Python 3.8+ for inventory helper:
  ```bash
  python3 -m pip install cryptography
  ```
- (Optional) A CBOM generator: CycloneDX `cdxgen`, or `cbomkit-theia` for container/directory crypto discovery.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance |
|----|------------------------|-----------|
| T1573 | Encrypted Channel | Migration secures encrypted channels (TLS/VPN/SSH) that protect data in transit; cryptographic inventory of these channels also underpins detection of adversary-controlled encrypted C2. |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | RSA/ECDH key exchange — exact asymmetric primitives broken by CRQC and replaced by ML-KEM hybrids. |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | AES and other symmetric ciphers; quantum-weakened by Grover, mitigated by 256-bit keys rather than replacement. |

## Workflow

### 1. Confirm PQC algorithm availability
```bash
openssl version
# List quantum-safe KEMs and signatures available in this OpenSSL build
openssl list -kem-algorithms | grep -Ei 'mlkem|kyber'
openssl list -signature-algorithms | grep -Ei 'mldsa|dilithium|slhdsa|sphincs'
openssl list -tls-groups 2>/dev/null | grep -Ei 'mlkem'
```
If using oqs-provider on OpenSSL 3.0–3.4, activate it in `openssl.cnf`:
```ini
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[default_sect]
activate = 1
[oqsprovider_sect]
activate = 1
```

### 2. Build cryptographic inventory (CBOM)
Generate CycloneDX CBOM from code repo or container with `cbomkit-theia` / `cdxgen`:
```bash
# Directory / container image crypto discovery
cbomkit-theia dir ./myapp --output cbom.json
# or with cdxgen (Java keystores, certs, source-level algorithms)
cdxgen -t java --include-crypto -o cbom.json ./myapp
```
Enumerate TLS algorithms and certificate signature schemes across live endpoints with helper `agent.py scan` (below), and public-key strength of any certificate:
```bash
openssl x509 -in server.crt -noout -text | grep -E 'Signature Algorithm|Public Key'
```

### 3. Classify and prioritize by HNDL exposure
For each inventoried asset, record: algorithm, key size, where key lives, data sensitivity, and **data lifetime**. Prioritize migration where `data_lifetime_years + migration_time > years_until_CRQC` (Mosca's inequality). Long-lived confidential data over public networks ranks highest; ephemeral internal traffic ranks lower. Hash-based signature roots-of-trust (firmware signing) are also high priority because they protect long-lived trust anchors.

### 4. Generate ML-KEM and ML-DSA key material
```bash
# ML-KEM-768 (key establishment) keypair
openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key
# OpenSSL 3.0-3.4 + oqs-provider uses lowercase 'mlkem768'
# openssl genpkey -algorithm mlkem768 -out mlkem768.key
# ML-DSA-65 (signature) keypair
openssl genpkey -algorithm ML-DSA-65 -out mldsa65.key
openssl pkey -in mldsa65.key -pubout -out mldsa65.pub
```

### 5. Issue PQC (ML-DSA) certificate
```bash
# Self-signed ML-DSA-65 certificate for testing
openssl req -new -x509 -key mldsa65.key -out mldsa65.crt -days 365 \
  -subj "/CN=pqc-test.example.com"
openssl x509 -in mldsa65.crt -noout -text | grep -A1 'Signature Algorithm'
```

### 6. Sign and verify with ML-DSA
```bash
echo "firmware-image-v2.bin" > artifact.txt
openssl dgst -sign mldsa65.key -out artifact.sig artifact.txt
openssl dgst -verify mldsa65.pub -signature artifact.sig artifact.txt
# -> "Verified OK"
```

### 7. Deploy and test hybrid TLS key exchange
Run TLS 1.3 server and force hybrid group `X25519MLKEM768` (classical X25519 + ML-KEM-768):
```bash
# Server (use a classical or ML-DSA cert/key)
openssl s_server -accept 4433 -www -tls1_3 \
  -cert mldsa65.crt -key mldsa65.key -groups X25519MLKEM768
# Client — negotiate the hybrid group and confirm it was used
openssl s_client -connect localhost:4433 -tls1_3 -groups X25519MLKEM768 \
  </dev/null 2>/dev/null | grep -E 'Negotiated|Server Temp Key|Cipher'
```
For external endpoints, confirm support against public PQC test server:
```bash
openssl s_client -groups X25519MLKEM768 -tls1_3 -connect pq.cloudflareresearch.com:443 </dev/null
```

### 8. Enable hybrid PQC on production TLS terminators
Configure web server / load balancer to offer hybrid group while keeping classical fallback for old clients. NGINX with OpenSSL 3.5+:
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;   # hybrid first, classical fallback
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
}
```
Reload and verify with s_client command from step 7 against live host.

### 9. Establish crypto-agility and rotation plan
Centralize algorithm selection (config, not code), record key/cert expiry, and schedule re-keying. Re-run inventory (step 2) on cadence to confirm no quantum-vulnerable-only algorithms remain on prioritized assets, and track residual RSA/ECDH usage to zero on high-HNDL paths.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| FIPS 203 (ML-KEM) | KEM standard | https://csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (ML-DSA) | Signature standard | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (SLH-DSA) | Hash-based signature standard | https://csrc.nist.gov/pubs/fips/205/final |
| NIST SP 1800-38 | Migration practice guide / crypto discovery | https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms |
| OpenSSL 3.5 | Native ML-KEM/ML-DSA/SLH-DSA + hybrid groups | https://www.openssl.org |
| oqs-provider / liboqs | PQC for OpenSSL 3.0–3.4 | https://github.com/open-quantum-safe/oqs-provider |
| CycloneDX CBOM | Cryptography Bill of Materials spec | https://cyclonedx.org/capabilities/cbom/ |
| CBOMkit / cbomkit-theia | Crypto discovery & CBOM generation | https://github.com/cbomkit/cbomkit-theia |

## Algorithm Reference

| Classical (broken/weakened) | Quantum-safe replacement | Standard | Use |
|-----------------------------|--------------------------|----------|-----|
| RSA / ECDH / DH key exchange | ML-KEM-512/768/1024 (hybrid: X25519MLKEM768) | FIPS 203 | Key establishment |
| RSA / ECDSA / EdDSA signatures | ML-DSA-44/65/87 | FIPS 204 | General signatures |
| (backup signature) | SLH-DSA (SPHINCS+) | FIPS 205 | Conservative/firmware signing |
| AES-128 | AES-256 | FIPS 197 | Symmetric (Grover-hardened) |
| SHA-256 | SHA-384/512, SHA-3 | FIPS 180-4/202 | Hashing |

## Validation Criteria

- [ ] OpenSSL 3.5+ (or 3.x + oqs-provider) confirmed exposing ML-KEM and ML-DSA.
- [ ] Cryptographic inventory / CBOM produced covering algorithms, keys, certs, and protocols.
- [ ] Assets classified and prioritized by HNDL exposure (Mosca's inequality applied).
- [ ] ML-KEM-768 and ML-DSA-65 keypairs generated successfully.
- [ ] PQC (ML-DSA) certificate issued and its signature algorithm verified.
- [ ] Sign/verify round trip with ML-DSA returns "Verified OK".
- [ ] Hybrid `X25519MLKEM768` key exchange negotiated and confirmed on test endpoint.
- [ ] Production TLS terminator offers hybrid group with classical fallback.
- [ ] Crypto-agility/rotation plan documented and inventory re-run scheduled.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/migrating-to-post-quantum-cryptography
