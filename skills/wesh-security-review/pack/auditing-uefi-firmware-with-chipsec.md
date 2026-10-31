---
name: auditing-uefi-firmware-with-chipsec
description: Use Intel CHIPSEC to assess platform firmware configuration, SPI flash write protection, BIOS lock, SMM/SMRR, and Secure Boot variable state, dump SPI flash, and triage UEFI variables for firmware-level threats.
subdomain: hardware-firmware-security
facing: defense
mitre_attack:
- T1542.001
nist_csf:
- ID.AM-02
upstream: auditing-uefi-firmware-with-chipsec@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** CHIPSEC loads kernel driver and reads/writes low-level hardware registers, SPI flash, and SMM. Run it only on systems you own or are explicitly authorized to assess, ideally on dedicated test hardware. Misuse (especially write/modify modules) can brick machine. Never run write-capable modules on production systems.

## Prerequisites

- Physical or admin/root access to target x86 platform (Intel or AMD)
- Linux (root) or Windows (Administrator), or UEFI shell environment
- Ability to load kernel driver (Secure Boot may need to allow CHIPSEC driver, or use `--no_driver` for limited checks)
- Python 3.8+ and C compiler/build tools for kernel module on Linux
- Dedicated test hardware strongly recommended

Install CHIPSEC:

```bash
# From PyPI
pip install chipsec
# Or from source (builds the kernel helper/driver)
git clone https://github.com/chipsec/chipsec
cd chipsec
python setup.py install        # builds and installs, including the Linux driver
# Verify
sudo chipsec_main --help
sudo chipsec_util --help
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1542.001 | Pre-OS Boot: System Firmware | Persistence / Defense Evasion |

CHIPSEC defends against T1542.001 by verifying that controls preventing unauthorized firmware modification are enabled. A FAIL on `common.bios_wp` (BIOS not write-protected) or `chipsec.modules.common.spi_lock` (flash descriptor unlocked) means attacker with OS privileges could rewrite SPI flash and implant persistent firmware — exactly precondition for this technique.

## Workflow

### Step 1: Run full automated test suite
`chipsec_main` with no module argument runs every applicable security check for detected platform and prints summary of PASS/FAIL/WARNING/INFORMATION results.

```bash
sudo chipsec_main
# Save machine-readable output for reporting / diffing
sudo chipsec_main -j results.json -x results.xml -l chipsec.log
```

### Step 2: Run core firmware-protection modules individually
The `common` module group contains OEM-independent security checks. Run group or specific modules:

```bash
# Run the whole common group
sudo chipsec_main -m common
# BIOS write protection: checks BIOS_CNTL BLE/SMM_BWP and SPI protected ranges
sudo chipsec_main -m common.bios_wp
# SPI flash descriptor lock (FLOCKDN) — are flash region accesses locked?
sudo chipsec_main -m common.spi_lock
# SMRR programming — protects SMRAM from cache-based attacks
sudo chipsec_main -m common.smrr
# SMM BIOS write protection
sudo chipsec_main -m common.smm
# S3 resume boot-script protection (against bootscript table attacks)
sudo chipsec_main -m common.uefi.s3bootscript
```

### Step 3: Verify Secure Boot variable protection
```bash
# Checks that Secure Boot UEFI variables are properly protected
sudo chipsec_main -m common.secureboot.variables
# To actively test write protection of the variables (test hardware ONLY):
sudo chipsec_main -m common.secureboot.variables -a modify
```

### Step 4: Inspect SPI flash region access permissions
```bash
# Report SPI flash regions, descriptor, and access permissions
sudo chipsec_util spi info
# Check the SPI access-control module
sudo chipsec_main -m common.spi_access
```

### Step 5: Dump SPI flash for offline forensics
Dumping flash lets you decode firmware volumes and compare against known-good OEM image.

```bash
# Dump the entire SPI flash to a file
sudo chipsec_util spi dump rom.bin
# Decode the dumped image: extracts firmware volumes, files, NVRAM variables, etc.
sudo chipsec_util decode rom.bin
```

### Step 6: Enumerate and triage UEFI variables
```bash
# List all UEFI variables from the runtime interface
sudo chipsec_util uefi var-list
# List variables directly from the SPI image (offline)
sudo chipsec_util uefi var-find PK
sudo chipsec_util uefi var-read db <GUID> db.bin
# Decode the UEFI firmware structure
sudo chipsec_util uefi decode rom.bin
```

### Step 7: Limited assessment without kernel driver
Where loading driver is impossible (locked-down Secure Boot), some checks still run read-only.

```bash
sudo chipsec_main -n            # --no_driver: skip checks that need the driver
sudo chipsec_main -p <PLATFORM> # force platform code if auto-detect fails
```

### Step 8: Triage results and report
- **FAIL** on `bios_wp` / `spi_lock` → firmware is rewritable from OS: high risk for T1542.001.
- **FAIL** on `secureboot.variables` → Secure Boot policy can be tampered.
- Compare the `spi dump` against OEM's known-good image (hash firmware volumes) to detect unauthorized modification.
- Record platform, BIOS version, and every FAIL/WARNING with relevant register values for report.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| chipsec_main | Automated platform-security test suite | https://github.com/chipsec/chipsec |
| chipsec_util | Manual hardware/firmware access (spi, uefi, decode) | https://chipsec.github.io/ |
| UEFITool | GUI/CLI parsing of dumped UEFI images | https://github.com/LongSoft/UEFITool |
| Binarly fwhunt | Firmware vulnerability/implant hunting rules | https://github.com/binarly-io/fwhunt-scan |
| NSA UEFI Secure Boot guidance | Hardening reference | https://media.defense.gov/ |

## Core Module Reference

| Module | Checks |
|--------|--------|
| common.bios_wp | BIOS_CNTL BLE / SMM_BWP and SPI Protected Ranges |
| common.spi_lock | SPI flash descriptor FLOCKDN |
| common.spi_access | SPI flash region read/write permissions |
| common.smrr | System Management Range Registers programming |
| common.smm | SMM BIOS write protection |
| common.secureboot.variables | Secure Boot variable protection |
| common.uefi.s3bootscript | S3 resume boot-script protection |

## Validation Criteria

- [ ] CHIPSEC installed and driver loads (or `-n` documented if not)
- [ ] Full `chipsec_main` suite executed with JSON/XML/log output saved
- [ ] `common.bios_wp` result interpreted (write protection state)
- [ ] `common.spi_lock` / `spi_access` result interpreted (descriptor lock)
- [ ] SMRR/SMM module results recorded
- [ ] Secure Boot variable protection checked
- [ ] SPI flash dumped and decoded for offline analysis
- [ ] UEFI variables enumerated and triaged
- [ ] All FAIL/WARNING findings documented with platform/BIOS version
- [ ] Write/modify modules NOT run on production hardware

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-uefi-firmware-with-chipsec
