---
name: implementing-immutable-backup-with-restic
description: Implements ransomware-resistant backups using restic with S3-compatible Object Lock (AWS S3, MinIO, Backblaze B2), automating backup creation, integrity checks via restic check --read-data, retention enforcement, and restore testing.
subdomain: ransomware-defense
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1486
- T1490
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
upstream: implementing-immutable-backup-with-restic@54a7988 Apache-2.0, modified by wesh
---
Not for: as the sole backup solution without also maintaining offline/air-gapped copies. Object lock protects against logical deletion but not physical storage failure.

## Prerequisites

- restic binary installed (https://restic.readthedocs.io/)
- S3-compatible storage with Object Lock enabled (AWS S3, MinIO, Backblaze B2)
- Python 3.8+ with subprocess module
- AWS CLI or MinIO client (mc) configured for bucket access
- Sufficient storage for backup repository (typically 2-3x source data with deduplication)

## Workflow

### Step 1: Initialize Restic Repository with Encryption

Create encrypted restic repository on S3-compatible storage with object lock enabled. Restic uses AES-256-CTR for encryption with Poly1305-AES for authentication, ensuring backup data is both confidential and tamper-evident.

### Step 2: Configure Object Lock Retention

Enable S3 Object Lock in Compliance mode on backup bucket to prevent any principal (including root) from deleting or modifying objects during retention period. Set retention to match your backup window requirements (typically 30-90 days).

### Step 3: Automate Backup and Verification

Schedule backup operations with post-backup integrity verification using `restic check --read-data` which downloads and verifies every data blob against its stored checksum. Log results and alert on any integrity failures.

### Step 4: Test Restore Procedures

Periodically restore random files from backup snapshots to temporary location and compare checksums against original to validate end-to-end backup integrity. Document restore times for RTO planning.

## Key Concepts

| Term | Definition |
|------|------------|
| **Object Lock** | S3 feature that prevents object deletion or overwrite for specified retention period |
| **Compliance Mode** | Object Lock mode where even root account cannot delete objects before retention expires |
| **Deduplication** | Restic stores data in content-addressable chunks, deduplicating across all snapshots |
| **3-2-1-1-0** | 3 copies, 2 media types, 1 offsite, 1 immutable, 0 errors in verification |

## Tools & Systems

- **restic**: Fast, secure, cross-platform backup tool with built-in encryption and deduplication
- **resticpy**: Python wrapper for restic CLI operations
- **AWS S3 Object Lock**: WORM storage for tamper-proof backup retention
- **MinIO**: Self-hosted S3-compatible storage with Object Lock support

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-immutable-backup-with-restic
