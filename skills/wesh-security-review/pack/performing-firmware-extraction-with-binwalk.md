---
name: performing-firmware-extraction-with-binwalk
description: Performs firmware image extraction and analysis using binwalk to identify embedded filesystems, compressed archives, bootloaders, kernel images, and cryptographic material.
subdomain: firmware-analysis
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
nist_csf:
- ID.RA-01
- PR.PS-01
- DE.AE-02
upstream: performing-firmware-extraction-with-binwalk@54a7988 Apache-2.0, modified by wesh
---
Not for: analyzing standard desktop application binaries or malware samples that are not firmware images; use dedicated malware analysis tools instead.

## Prerequisites

- binwalk v3.x installed (`pip install binwalk3` or from system package manager)
- Python 3.8+ with standard libraries (struct, math, hashlib, subprocess)
- SquashFS tools (`unsquashfs`) for mounting extracted SquashFS filesystems
- Jefferson for JFFS2 filesystem extraction (`pip install jefferson`)
- Sasquatch for non-standard SquashFS variants used by vendors like TP-Link and D-Link
- `strings` utility (GNU binutils) for string extraction
- Optional: firmware-mod-kit for repacking modified firmware images

## Workflow

### Step 1: Initial Firmware Reconnaissance

Perform signature scan to identify embedded file types and their offsets:

```bash
# Basic signature scan - identify all recognized file types
binwalk firmware.bin
# Scan with verbose output showing confidence levels
binwalk -v firmware.bin
# Scan for specific file types only
binwalk -y "squashfs" firmware.bin
binwalk -y "gzip\|lzma\|xz" firmware.bin
# Opcode scan to identify CPU architecture
binwalk -A firmware.bin
# Scan for raw strings to find version info, URLs, credentials
binwalk -R "password" firmware.bin
binwalk -R "http://" firmware.bin
```

### Step 2: Entropy Analysis

Analyze entropy to identify encrypted, compressed, and plaintext regions:

```bash
# Generate entropy plot
binwalk -E firmware.bin
# Entropy with specific block size for higher resolution
binwalk -E -K 256 firmware.bin
# Combined entropy and signature scan
binwalk -BE firmware.bin
```

Interpreting entropy values:
- **0.0 - 1.0**: Empty or padding regions (null bytes, 0xFF fill)
- **1.0 - 5.0**: Plaintext data, code, ASCII strings, configuration
- **5.0 - 7.0**: Compressed data (gzip, LZMA, zlib)
- **7.0 - 7.99**: Strongly compressed or encrypted data
- **~8.0**: Maximum entropy, likely encrypted or random data

### Step 3: Extract Embedded Files

Extract all identified components from firmware image:

```bash
# Automatic extraction of known file types
binwalk -e firmware.bin
# Recursive extraction (matryoshka mode) for nested archives
binwalk -Me firmware.bin
# Recursive extraction with depth limit
binwalk -Me -d 5 firmware.bin
# Extract specific file type with custom handler
binwalk -D "squashfs filesystem:squashfs:unsquashfs %e" firmware.bin
# Manual extraction of data at a known offset
dd if=firmware.bin of=extracted.squashfs bs=1 skip=327680 count=4194304
```

### Step 4: Mount and Inspect Extracted Filesystems

Mount extracted filesystems for deep inspection:

```bash
# Mount SquashFS filesystem
mkdir /tmp/squashfs_root
unsquashfs -d /tmp/squashfs_root extracted.squashfs
# Mount CramFS filesystem
mkdir /tmp/cramfs_root
mount -t cramfs -o loop extracted.cramfs /tmp/cramfs_root
# Extract JFFS2 filesystem
jefferson extracted.jffs2 -d /tmp/jffs2_root
# Inspect the extracted filesystem
ls -la /tmp/squashfs_root/
find /tmp/squashfs_root -name "*.conf" -o -name "*.cfg" -o -name "*.key"
find /tmp/squashfs_root -name "passwd" -o -name "shadow"
```

### Step 5: String Analysis and Credential Discovery

Search extracted filesystem and raw firmware for sensitive data:

```bash
# Extract all printable strings
strings -a firmware.bin > all_strings.txt
strings -n 12 firmware.bin | sort -u > long_strings.txt
# Search for credentials and secrets
grep -rni "password\|passwd\|secret\|api_key\|token" /tmp/squashfs_root/etc/
grep -rni "BEGIN.*PRIVATE KEY" /tmp/squashfs_root/
# Find hardcoded URLs and endpoints
grep -rnoE "https?://[a-zA-Z0-9./?=_-]+" /tmp/squashfs_root/
# Search for certificate files
find /tmp/squashfs_root -name "*.pem" -o -name "*.crt" -o -name "*.key" -o -name "*.p12"
# Identify busybox and service versions
strings /tmp/squashfs_root/bin/busybox | grep "BusyBox v"
cat /tmp/squashfs_root/etc/banner 2>/dev/null
```

### Step 6: Generate Firmware Analysis Report

Compile comprehensive extraction and analysis findings:

```
Report should include:
- Firmware metadata (vendor, model, version, build date)
- Identified components with offsets and sizes (bootloader, kernel, filesystem, config)
- Entropy analysis summary with regions of interest
- Extracted filesystem structure and key contents
- Discovered credentials, keys, certificates
- Identified services, daemons, and their versions
- Known CVEs applicable to identified component versions
- Recommendations for hardening or vulnerability remediation
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Firmware** | Software embedded in hardware devices providing low-level control; typically contains bootloader, kernel, root filesystem, and configuration data |
| **Entropy Analysis** | Statistical measurement of randomness in binary data; high entropy indicates encryption or compression, low entropy indicates plaintext or structured data |
| **SquashFS** | Read-only compressed filesystem commonly used in embedded Linux devices; supports LZMA, gzip, LZO, and zstd compression |
| **Magic Bytes** | Known byte sequences at fixed offsets that identify file types; binwalk uses database of magic signatures to detect embedded files |
| **Matryoshka Extraction** | Recursive extraction mode where binwalk re-scans extracted files for additional embedded content, handling deeply nested archives |
| **CramFS** | Compressed ROM filesystem designed for embedded systems with limited flash storage; supports only zlib compression |
| **JFFS2** | Journalling Flash File System version 2, designed for NOR and NAND flash memory in embedded devices |

## Tools & Systems

- **binwalk**: Primary firmware analysis tool for signature scanning, entropy analysis, and automated extraction of embedded files
- **unsquashfs**: SquashFS extraction utility for mounting read-only compressed filesystems found in router and IoT firmware
- **jefferson**: Python tool for extracting JFFS2 flash filesystem images commonly found in embedded devices
- **sasquatch**: Patched SquashFS utility supporting non-standard vendor-modified SquashFS variants
- **firmware-mod-kit**: Toolkit for extracting, modifying, and repacking firmware images for security testing

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-firmware-extraction-with-binwalk
