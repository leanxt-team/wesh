---
name: acquiring-disk-image-with-dd-and-dcfldd
description: Create forensically sound bit-for-bit disk images with dd or dcfldd on a Linux forensic workstation, preserving evidence integrity through hash verification (MD5/SHA) during acquisition.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1006
- T1005
- T1025
- T1074.001
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: acquiring-disk-image-with-dd-and-dcfldd@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- Linux-based forensic workstation (SIFT, Kali, or any Linux distro)
- `dd` (pre-installed on all Linux systems) or `dcfldd` (enhanced forensic version)
- Write-blocker hardware or software write-blocking configured
- Destination drive with sufficient storage (larger than source)
- Root/sudo privileges on forensic workstation
- SHA-256 or MD5 hashing utilities (`sha256sum`, `md5sum`)

## Workflow

### Step 1: Identify Target Device and Enable Write Protection

```bash
# List all connected block devices to identify the target
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL
# Verify the device details
fdisk -l /dev/sdb
# Enable software write-blocking (if no hardware blocker)
blockdev --setro /dev/sdb
# Verify read-only status
blockdev --getro /dev/sdb
# Output: 1 (means read-only is enabled)
# Alternatively, use udev rules for persistent write-blocking
echo 'SUBSYSTEM=="block", ATTRS{serial}=="WD-WCAV5H861234", ATTR{ro}="1"' > /etc/udev/rules.d/99-writeblock.rules
udevadm control --reload-rules
```

### Step 2: Prepare Destination and Document Source

```bash
# Create case directory structure
mkdir -p /cases/case-2024-001/{images,hashes,logs,notes}
# Document source drive information
hdparm -I /dev/sdb > /cases/case-2024-001/notes/source_drive_info.txt
# Record the serial number and model
smartctl -i /dev/sdb >> /cases/case-2024-001/notes/source_drive_info.txt
# Pre-hash the source device
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_before.txt
```

### Step 3: Acquire Image Using dd

```bash
# Basic dd acquisition with progress and error handling
dd if=/dev/sdb of=/cases/case-2024-001/images/evidence.dd \
   bs=4096 \
   conv=noerror,sync \
   status=progress 2>&1 | tee /cases/case-2024-001/logs/dd_acquisition.log
# For compressed images to save space
dd if=/dev/sdb bs=4096 conv=noerror,sync status=progress | \
   gzip -c > /cases/case-2024-001/images/evidence.dd.gz
# Using dd with a specific count for partial acquisition
dd if=/dev/sdb of=/cases/case-2024-001/images/first_1gb.dd \
   bs=1M count=1024 status=progress
```

### Step 4: Acquire Using dcfldd (Preferred Forensic Method)

```bash
# Install dcfldd if not present
apt-get install dcfldd
# Acquire image with built-in hashing and split output
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256,md5 \
   hashwindow=1G \
   hashlog=/cases/case-2024-001/hashes/acquisition_hashes.txt \
   bs=4096 \
   conv=noerror,sync \
   errlog=/cases/case-2024-001/logs/dcfldd_errors.log
# Split large images into manageable segments
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/split_hashes.txt \
   bs=4096 \
   split=2G \
   splitformat=aa
# Acquire with verification pass
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/verification.txt \
   vf=/cases/case-2024-001/images/evidence.dd \
   verifylog=/cases/case-2024-001/logs/verify.log
```

### Step 5: Verify Image Integrity

```bash
# Hash the acquired image
sha256sum /cases/case-2024-001/images/evidence.dd | \
   tee /cases/case-2024-001/hashes/image_hash.txt
# Compare source and image hashes
diff <(sha256sum /dev/sdb | awk '{print $1}') \
     <(sha256sum /cases/case-2024-001/images/evidence.dd | awk '{print $1}')
# If using split images, verify each segment
sha256sum /cases/case-2024-001/images/evidence.dd.* | \
   tee /cases/case-2024-001/hashes/split_image_hashes.txt
# Re-hash source to confirm no changes occurred
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_after.txt
diff /cases/case-2024-001/hashes/source_hash_before.txt \
     /cases/case-2024-001/hashes/source_hash_after.txt
```

### Step 6: Document Acquisition Process

```bash
# Generate acquisition report
cat << 'EOF' > /cases/case-2024-001/notes/acquisition_report.txt
DISK IMAGE ACQUISITION REPORT
==============================
Case Number: 2024-001
Date/Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Examiner: [Name]
Source Device: /dev/sdb
Model: [from hdparm output]
Serial: [from hdparm output]
Size: [from fdisk output]
Acquisition Tool: dcfldd v1.9.1
Block Size: 4096
Write Blocker: [Hardware/Software model]
Image File: evidence.dd
Image Hash (SHA-256): [from hash file]
Source Hash (SHA-256): [from hash file]
Hash Match: YES/NO
Errors During Acquisition: [from error log]
EOF
# Compress logs for archival
tar -czf /cases/case-2024-001/acquisition_package.tar.gz \
   /cases/case-2024-001/hashes/ \
   /cases/case-2024-001/logs/ \
   /cases/case-2024-001/notes/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Bit-for-bit copy | Exact replica of source including unallocated space and slack space |
| Write blocker | Hardware or software mechanism preventing writes to evidence media |
| Hash verification | Cryptographic hash comparing source and image to prove integrity |
| Block size (bs) | Transfer chunk size affecting speed; 4096 or 64K typical for forensics |
| conv=noerror,sync | Continue on read errors and pad with zeros to maintain offset alignment |
| Chain of custody | Documented trail proving evidence has not been tampered with |
| Split imaging | Breaking large images into smaller files for storage and transport |
| Raw/dd format | Bit-for-bit image format without metadata container overhead |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| dd | Standard Unix disk duplication utility for raw imaging |
| dcfldd | DoD Computer Forensics Laboratory enhanced version of dd with hashing |
| dc3dd | Another forensic dd variant from DoD Cyber Crime Center |
| sha256sum | SHA-256 hash calculation for integrity verification |
| blockdev | Linux command to set block device read-only mode |
| hdparm | Drive identification and parameter reporting |
| smartctl | S.M.A.R.T. data retrieval for drive health and identification |
| lsblk | Block device enumeration and identification |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/acquiring-disk-image-with-dd-and-dcfldd
