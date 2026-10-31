---
name: implementing-aws-nitro-enclave-security
description: Build AWS Nitro Enclave confidential computing environments using nitro-cli to create enclave images, configure attestation-aware KMS policies with PCR condition keys, validate attestation documents against the Nitro PKI root, and set up vsock/kmstool-enclave-cli pipelines for processing PII, keys, and health records.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T0816
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: implementing-aws-nitro-enclave-security@54a7988 Apache-2.0, modified by wesh
---
Not for: the workload does not handle sensitive data that requires hardware-level isolation, when the instance type does not support Nitro Enclaves (requires Nitro-based instances with at least 4 vCPUs), or when latency constraints make the vsock communication overhead unacceptable.

## Prerequisites

- AWS account with permissions to launch Nitro-capable EC2 instances (m5.xlarge or larger, C5, R5, M6i families)
- AWS CLI v2 and the `nitro-cli` toolset installed on parent EC2 instance (Amazon Linux 2 or AL2023)
- Docker installed on parent instance for building enclave image files (EIF)
- AWS KMS symmetric key with key policy permissions for enclave's IAM role
- The `aws-nitro-enclaves-sdk-c` or Python `aws-encryption-sdk` for enclave-side KMS operations
- Nitro Enclaves allocator service configured with sufficient memory and vCPU allocation in `/etc/nitro_enclaves/allocator.yaml`

## Workflow

### Step 1: Configure Nitro Enclaves Environment

Set up parent EC2 instance to support enclave launches:

- **Install Nitro Enclaves CLI**: On Amazon Linux 2, install tools and allocator:
  ```bash
  sudo amazon-linux-extras install aws-nitro-enclaves-cli
  sudo yum install aws-nitro-enclaves-cli-devel -y
  sudo systemctl enable --now nitro-enclaves-allocator.service
  sudo systemctl enable --now docker
  sudo usermod -aG ne ec2-user
  sudo usermod -aG docker ec2-user
  ```
- **Configure memory and CPU allocation**: Edit `/etc/nitro_enclaves/allocator.yaml` to reserve resources for enclave. enclave requires dedicated memory i.e. carved from parent instance:
  ```yaml
  ---
  memory_mib: 4096
  cpu_count: 2
  ```
  Restart allocator: `sudo systemctl restart nitro-enclaves-allocator.service`
- **Verify setup**: Run `nitro-cli describe-enclaves` to confirm CLI can communicate with Nitro hypervisor. empty JSON array `[]` indicates no enclaves are running and setup is correct.

### Step 2: Build Enclave Image File (EIF)

Package sensitive workload into signed enclave image:

- **Create application Dockerfile**: enclave runs minimal Linux environment. application communicates exclusively through vsock:
  ```dockerfile
  FROM amazonlinux:2
  RUN yum install -y python3 python3-pip && \
      pip3 install boto3 cbor2 cryptography requests
  COPY enclave_app.py /app/enclave_app.py
  WORKDIR /app
  CMD ["python3", "enclave_app.py"]
  ```
- **Build EIF with nitro-cli**: Convert Docker image into enclave image file, capturing PCR measurements:
  ```bash
  docker build -t enclave-app:latest .
  nitro-cli build-enclave \
    --docker-uri enclave-app:latest \
    --output-file enclave-app.eif
  ```
  Output contains three critical PCR values:
  - **PCR0**: SHA-384 hash of enclave image file (full image digest)
  - **PCR1**: SHA-384 hash of Linux kernel and bootstrap process
  - **PCR2**: SHA-384 hash of application code
  Record these values; they are used in KMS key policies for attestation-based access control.

- **Build signed EIF** (recommended for production): Generate signing certificate and use it to produce PCR8:
  ```bash
  openssl ecparam -name secp384r1 -genkey -noout -out enclave_key.pem
  openssl req -new -key enclave_key.pem -sha384 \
    -nodes -subj "/CN=Enclave Signer" -out enclave_csr.pem
  openssl x509 -req -days 365 -in enclave_csr.pem \
    -signkey enclave_key.pem -sha384 -out enclave_cert.pem
  nitro-cli build-enclave \
    --docker-uri enclave-app:latest \
    --output-file enclave-app.eif \
    --private-key enclave_key.pem \
    --signing-certificate enclave_cert.pem
  ```
  PCR8 (signing certificate hash) enables KMS policies that trust any image signed by specific certificate, allowing image updates without changing policy.

### Step 3: Configure KMS Attestation-Based Key Policies

Create KMS key policy that restricts decryption to verified enclave:

- **Policy using PCR0 (image hash)**: This locks key to specific enclave build. Any code change produces new PCR0, requiring policy update:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowEnclaveDecrypt",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::111122223333:role/EnclaveParentRole"
        },
        "Action": [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        "Resource": "*",
        "Condition": {
          "StringEqualsIgnoreCase": {
            "kms:RecipientAttestation:ImageSha384": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
          }
        }
      }
    ]
  }
  ```
- **Policy using PCR8 (signing certificate)**: Trusts any enclave signed with specific certificate, enabling image rotation without policy changes:
  ```json
  {
    "Condition": {
      "StringEqualsIgnoreCase": {
        "kms:RecipientAttestation:PCR8": "ab3456789012345678901234567890123456789012345678901234567890123456789012345678901234567890abcdef"
      }
    }
  }
  ```
- **Multi-PCR policy for defense in depth**: Combine PCR0 (image) and PCR1 (kernel) to ensure both application and boot environment match expected values:
  ```json
  {
    "Condition": {
      "StringEqualsIgnoreCase": {
        "kms:RecipientAttestation:PCR0": "<pcr0-hex>",
        "kms:RecipientAttestation:PCR1": "<pcr1-hex>"
      }
    }
  }
  ```
- **IAM role policy**: parent instance's IAM role must have `kms:Decrypt` permission, but KMS key policy condition ensures actual decryption only succeeds when request originates from valid enclave with correct attestation document attached.

### Step 4: Implement Secure Vsock Communication

Establish parent-to-enclave communication channel:

- **Vsock architecture**: only way enclave communicates with outside world is through vsock (virtual socket). Vsock uses CID (Context Identifier) and port number. parent instance CID is always `3`, and enclave CID is assigned at launch.
- **Parent-side proxy server**: parent runs proxy that forwards KMS API calls from enclave through vsock to AWS KMS endpoint:
  ```python
  import socket
  import json
  import boto3
  VSOCK_CID = 3  # Parent CID
  VSOCK_PORT = 5000
  def start_proxy():
      sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
      sock.bind((VSOCK_CID, VSOCK_PORT))
      sock.listen(5)
      kms_client = boto3.client('kms', region_name='us-east-1')
      while True:
          conn, addr = sock.accept()
          data = conn.recv(65536)
          request = json.loads(data.decode())
          if request['action'] == 'decrypt':
              response = kms_client.decrypt(
                  CiphertextBlob=bytes.fromhex(request['ciphertext']),
                  Recipient={
                      'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
                      'AttestationDocument': bytes.fromhex(request['attestation_doc'])
                  }
              )
              conn.sendall(json.dumps({
                  'ciphertext_for_recipient': response['CiphertextForRecipient'].hex()
              }).encode())
          conn.close()
  ```
- **Enclave-side client**: enclave application requests attestation document from Nitro Security Module (NSM) device at `/dev/nsm`, attaches it to KMS decrypt requests, and receives data encrypted to enclave's ephemeral public key:
  ```python
  import socket
  import json
  from cryptography.hazmat.primitives.asymmetric import rsa, padding
  from cryptography.hazmat.primitives import hashes, serialization
  PARENT_CID = 3
  VSOCK_PORT = 5000
  def get_attestation_document(public_key_der):
      """Request attestation document from NSM device."""
      # Uses the aws-nitro-enclaves-nsm-api
      # NSM provides: module_id, digest (SHA384), timestamp, PCRs,
      # certificate (from Nitro PKI), cabundle, public_key, user_data, nonce
      import nsm_util
      nsm_fd = nsm_util.nsm_lib_init()
      attestation_doc = nsm_util.nsm_get_attestation_doc(
          nsm_fd,
          public_key=public_key_der,
          user_data=None,
          nonce=None
      )
      return attestation_doc
  def decrypt_via_parent(ciphertext_hex):
      """Send decrypt request through vsock to parent proxy."""
      private_key = rsa.generate_private_key(
          public_exponent=65537, key_size=2048
      )
      public_key_der = private_key.public_key().public_bytes(
          serialization.Encoding.DER,
          serialization.PublicFormat.SubjectPublicKeyInfo
      )
      attestation_doc = get_attestation_document(public_key_der)
      sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
      sock.connect((PARENT_CID, VSOCK_PORT))
      sock.sendall(json.dumps({
          'action': 'decrypt',
          'ciphertext': ciphertext_hex,
          'attestation_doc': attestation_doc.hex()
      }).encode())
      response = json.loads(sock.recv(65536).decode())
      sock.close()
      # KMS encrypted the plaintext to the enclave's public key
      # Only the enclave's private key can decrypt it
      ciphertext_for_recipient = bytes.fromhex(
          response['ciphertext_for_recipient']
      )
      plaintext = private_key.decrypt(
          ciphertext_for_recipient,
          padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA256()),
              algorithm=hashes.SHA256(),
              label=None
          )
      )
      return plaintext
  ```

### Step 5: Validate Attestation Documents

Verify attestation documents from enclaves to establish trust:

- **Attestation document structure**: document is CBOR-encoded and COSE-signed (COSE_Sign1). It contains:
  - `module_id`: Identifier for NSM module
  - `digest`: Hashing algorithm (SHA-384)
  - `timestamp`: Unix epoch milliseconds when document was created
  - `pcrs`: Map of PCR index to measurement value (PCR0-PCR15)
  - `certificate`: NSM's x509 certificate, signed by Nitro PKI
  - `cabundle`: Certificate chain from NSM certificate to AWS Nitro root CA
  - `public_key`: enclave's ephemeral public key (provided at attestation request time)
  - `user_data`: Optional application-defined data (up to 512 bytes)
  - `nonce`: Optional nonce for freshness verification

- **Validation steps**:
  1. Decode COSE_Sign1 structure and extract payload and certificate
  2. Verify COSE signature using public key from embedded certificate
  3. Validate certificate chain from NSM certificate through CA bundle to AWS Nitro Attestation PKI root certificate (available at `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`)
  4. Check that root CA certificate matches expected AWS root: `aws.nitro-enclaves` CN
  5. Verify that no certificate in chain is expired at document's timestamp
  6. Compare PCR0, PCR1, PCR2 values against expected measurements from enclave build output
  7. If nonce was provided, verify it matches to prevent replay attacks

- **Attestation validation code**:
  ```python
  import cbor2
  from cose import CoseMessage
  from cryptography import x509
  from cryptography.x509.oid import NameOID
  def validate_attestation(attestation_bytes, expected_pcrs, expected_nonce=None):
      cose_msg = CoseMessage.decode(attestation_bytes)
      payload = cbor2.loads(cose_msg.payload)
      # Verify certificate chain
      cert = x509.load_der_x509_certificate(payload['certificate'])
      cabundle = [x509.load_der_x509_certificate(c) for c in payload['cabundle']]
      # Check root CA is AWS Nitro
      root = cabundle[-1]
      cn = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
      assert cn == 'aws.nitro-enclaves', f'Unexpected root CA: {cn}'
      # Verify PCR measurements
      pcrs = payload['pcrs']
      for idx, expected_value in expected_pcrs.items():
          actual = pcrs.get(idx, b'').hex()
          assert actual == expected_value, f'PCR{idx} mismatch: {actual}'
      # Verify nonce freshness
      if expected_nonce:
          assert payload.get('nonce') == expected_nonce, 'Nonce mismatch'
      return payload
  ```

### Step 6: Launch and Monitor Enclave

Run enclave and implement operational monitoring:

- **Launch enclave**:
  ```bash
  nitro-cli run-enclave \
    --eif-path enclave-app.eif \
    --cpu-count 2 \
    --memory 4096 \
    --enclave-cid 16 \
    --debug-mode
  ```
  Note: `--debug-mode` enables enclave console for development. Remove it in production as it allows reading enclave output, which breaks isolation guarantee.

- **Verify enclave status**:
  ```bash
  nitro-cli describe-enclaves
  ```
  Expected output includes `"State": "RUNNING"`, assigned `EnclaveCID`, memory, CPU count, and enclave flags.

- **Read enclave console** (debug mode only):
  ```bash
  nitro-cli console --enclave-id <enclave-id>
  ```

- **Terminate enclave**:
  ```bash
  nitro-cli terminate-enclave --enclave-id <enclave-id>
  ```

- **CloudWatch monitoring**: Configure parent instance to report enclave health metrics. Since enclave has no network access, health checks must go through vsock proxy:
  ```python
  # Parent-side health check over vsock
  def check_enclave_health(enclave_cid, port=5001):
      try:
          sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
          sock.settimeout(5)
          sock.connect((enclave_cid, port))
          sock.sendall(b'HEALTH_CHECK')
          response = sock.recv(1024)
          sock.close()
          return response == b'OK'
      except (socket.timeout, ConnectionRefusedError):
          return False
  ```

## Key Concepts

| Term | Definition |
|------|------------|
| **Nitro Enclave** | isolated virtual machine created by Nitro Hypervisor on Nitro-based EC2 instance with no persistent storage, no network access, and no interactive access, even from parent instance's root user |
| **Attestation Document** | A CBOR-encoded, COSE-signed document generated by Nitro Security Module containing PCR measurements, certificate chain to AWS Nitro root CA, and optional user-provided data |
| **PCR (Platform Configuration Register)** | SHA-384 hash measurements that uniquely identify enclave's image (PCR0), kernel/bootstrap (PCR1), application (PCR2), IAM role (PCR4), instance ID (PCR3), and signing certificate (PCR8) |
| **Vsock** | virtual socket providing sole communication channel between parent EC2 instance and its enclave, using CID (Context Identifier) and port addressing |
| **EIF (Enclave Image File)** | packaged enclave image built by nitro-cli from Docker image, containing kernel, ramdisk, and application, producing PCR measurements at build time |
| **Nitro Security Module (NSM)** | custom Linux device (`/dev/nsm`) inside enclave that provides attestation document generation and hardware random number generation |
| **COSE_Sign1** | CBOR Object Signing and Encryption single-signer structure used to sign attestation document with NSM's private key |
| **kms:RecipientAttestation** | AWS KMS condition key prefix that enables key policies to enforce that decrypt/generate operations only succeed when valid attestation document with matching PCR values is presented |

## Tools & Systems

- **nitro-cli**: AWS CLI tool for building enclave image files, launching/terminating enclaves, and reading enclave console output
- **AWS KMS**: Key Management Service that natively supports attestation-based condition keys for Nitro Enclaves, encrypting responses to enclave's ephemeral public key
- **aws-nitro-enclaves-sdk-c**: C SDK for enclave-side KMS operations that handles attestation document generation and vsock proxy communication
- **kmstool-enclave-cli**: Pre-built CLI tool (from SDK) that runs inside enclave to perform KMS Decrypt and GenerateRandom operations with attestation
- **Nitro Enclaves ACM**: AWS Certificate Manager integration that provisions TLS certificates inside enclaves for establishing HTTPS endpoints
- **CloudTrail**: Logs KMS API calls including `Decrypt` and `GenerateDataKey` operations that include `Recipient` parameters, enabling auditing of enclave-originated cryptographic operations

## Nitro Enclave Security Assessment

**Enclave Image**: enclave-tokenizer.eif
**Build Date**: 2026-03-19T14:30:00Z
**Instance Type**: m5.2xlarge
**Allocated Resources**: 2 vCPUs, 4096 MiB memory

### PCR Measurements
| PCR | Value | Bound in KMS Policy |
|-----|-------|---------------------|
| PCR0 (Image) | a1b2c3d4e5f6... | Yes |
| PCR1 (Kernel) | f6e5d4c3b2a1... | Yes |
| PCR2 (Application) | 1a2b3c4d5e6f... | No |
| PCR8 (Signing Cert) | 9f8e7d6c5b4a... | Yes (production) |

### KMS Key Policy Verification
- Key ARN: arn:aws:kms:us-east-1:111122223333:key/mrk-abc123
- Attestation condition: kms:RecipientAttestation:ImageSha384 = PCR0
- Signing cert condition: kms:RecipientAttestation:PCR8 = <cert-hash>
- Parent role: arn:aws:iam::111122223333:role/EnclaveParentRole
- Direct decrypt from parent: BLOCKED (attestation required)
- Decrypt from verified enclave: ALLOWED

### Security Posture
- [PASS] Debug mode disabled in production launch command
- [PASS] Vsock is only communication channel (no network interface)
- [PASS] Attestation document nonce verification implemented
- [PASS] Certificate chain validates to AWS Nitro root CA
- [WARN] PCR0 used in policy; consider PCR8 for deployment flexibility
- [FAIL] Health check endpoint does not verify enclave attestation freshness
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-aws-nitro-enclave-security
