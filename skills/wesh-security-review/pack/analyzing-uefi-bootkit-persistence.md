---
name: analyzing-uefi-bootkit-persistence
description: Analyzes UEFI bootkit persistence (SPI flash implants, ESP modifications, Secure Boot bypass, UEFI variable manipulation) using chipsec for firmware integrity verification, detecting known families like BlackLotus, LoJax, and MoonBounce.
subdomain: firmware-security
facing: defense
mitre_attack:
- T1542.001
- T1542.003
- T1553.006
- T1542
- T1014
nist_csf:
- ID.RA-01
- PR.PS-01
- PR.PS-02
upstream: analyzing-uefi-bootkit-persistence@54a7988 Apache-2.0, modified by wesh
---
Not for: standard MBR-based bootkits on legacy BIOS systems without UEFI; use MBR/VBR bootkit analysis instead.

## Prerequisites

- chipsec framework for SPI flash dumping, UEFI variable inspection, and firmware security modules
- UEFITool / UEFIExtract for firmware volume parsing and DXE driver extraction
- Python 3.8+ with struct, hashlib, subprocess, and os modules
- Bootable Linux live USB for offline analysis (avoid running compromised OS)
- Volatility 3 for memory forensics of boot-phase artifacts
- YARA with UEFI malware rule sets for pattern-based detection
- Access to vendor firmware baselines for integrity comparison

## Workflow

### Step 1: Dump SPI Flash Firmware

Acquire UEFI firmware from SPI flash chip for offline analysis:

```bash
# Using chipsec to dump SPI flash contents
python chipsec_util.py spi dump firmware_dump.rom
# Using flashrom as an alternative
flashrom -p internal -r firmware_dump.rom
# Verify dump integrity
sha256sum firmware_dump.rom
# Read SPI flash descriptor information
python chipsec_util.py spi info
# Check SPI flash region access permissions
python chipsec_main.py -m common.spi_access
# Verify BIOS write protection is enabled
python chipsec_main.py -m common.bios_wp
# Check SPI flash controller lock
python chipsec_main.py -m common.spi_lock
```

### Step 2: Inspect UEFI Variables

Enumerate and analyze UEFI variables for unauthorized modifications:

```bash
# List all UEFI variables on a live system
python chipsec_util.py uefi var-list
# List UEFI variables from a SPI flash dump
python chipsec_util.py uefi var-list-spi firmware_dump.rom
# Read specific Secure Boot variables
python chipsec_util.py uefi var-read SecureBoot 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read SetupMode 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read PK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
# Dump UEFI key databases for analysis
python chipsec_util.py uefi keys
# Check Secure Boot configuration module
python chipsec_main.py -m common.secureboot.variables
```

### Step 3: Analyze EFI System Partition (ESP)

Inspect ESP for unauthorized or modified boot components:

```bash
# Mount ESP (typically the first FAT32 partition, ~100-500MB)
mkdir /mnt/esp
mount /dev/sda1 /mnt/esp
# List all files on ESP with timestamps
find /mnt/esp -type f -exec ls -la {} \;
# Check for BlackLotus indicators - custom directory under ESP:/system32/
ls -la /mnt/esp/system32/ 2>/dev/null
# Verify Windows Boot Manager signature
sigcheck -a /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi
# Hash all EFI binaries for comparison against known-good values
find /mnt/esp -name "*.efi" -exec sha256sum {} \;
# Check for unauthorized .efi files outside standard directories
find /mnt/esp -name "*.efi" | grep -v "Microsoft\|Boot\|ubuntu\|grub"
# Look for grubx64.efi planted by BlackLotus
find /mnt/esp -name "grubx64.efi" -exec sha256sum {} \;
# Examine MeasuredBoot logs for anomalies (Windows)
# Logs located at C:\Windows\Logs\MeasuredBoot\
```

### Step 4: Scan Firmware for Known Bootkit Signatures

Analyze firmware dump for known UEFI malware patterns:

```bash
# Extract all firmware modules with UEFIExtract
UEFIExtract firmware_dump.rom all
# Generate firmware module whitelist from vendor baseline
python chipsec_main.py -m tools.uefi.whitelist -a generate,baseline.json,firmware_vendor.rom
# Compare current firmware against whitelist
python chipsec_main.py -m tools.uefi.whitelist -a check,baseline.json,firmware_dump.rom
# Scan firmware with UEFI-specific YARA rules
yara -r uefi_bootkits.yar firmware_dump.rom
# Scan extracted modules individually
find firmware_dump.rom.dump -name "*.efi" -exec yara -r uefi_bootkits.yar {} \;
# Check for modified CORE_DXE module (targeted by MoonBounce, CosmicStrand)
# Compare GUID and hash against vendor baseline
```

### Step 5: Detect Secure Boot Bypass Mechanisms

Check for known Secure Boot bypass techniques:

```bash
# Check if Secure Boot is enabled
python chipsec_main.py -m common.secureboot.variables
# Verify SMM (System Management Mode) protections
python chipsec_main.py -m common.smm
# Check SMM BIOS write protection
python chipsec_main.py -m common.bios_smi
# On Windows - check boot configuration for bypass indicators
bcdedit /enum firmware
bcdedit /v
# Check for testsigning/nointegritychecks/debug flags
bcdedit | findstr /i "testsigning nointegritychecks debug"
# Verify HVCI (Hypervisor-enforced Code Integrity) is not disabled
# BlackLotus sets HKLM:\...\DeviceGuard\...\HypervisorEnforcedCodeIntegrity Enabled=0
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled
# Check Secure Boot state via PowerShell
# Confirm-SecureBootUEFI returns True if properly enabled
```

### Step 6: Perform Boot Chain Integrity Verification

Verify every component in boot chain from firmware through kernel:

```bash
# Verify firmware integrity against vendor hash
sha256sum firmware_dump.rom
# Compare with vendor-published hash
# Verify bootloader signatures
sigcheck -a C:\Windows\Boot\EFI\bootmgfw.efi
sigcheck -a C:\Windows\System32\winload.efi
sigcheck -a C:\Windows\System32\ntoskrnl.exe
# Check for unsigned or invalid boot drivers
sigcheck -u -e C:\Windows\System32\drivers\
# Analyze Measured Boot logs for unexpected EFI_Boot_Services_Application entries
# BlackLotus components appear as EV_EFI_Boot_Services_Application
# Memory forensics for boot-phase artifacts
vol3 -f memory.dmp windows.modules
vol3 -f memory.dmp windows.driverscan
```

### Step 7: Document UEFI Bootkit Analysis Findings

Compile comprehensive analysis report:

```
Report should include:
- Firmware version, vendor, and platform identification
- SPI flash protection status (write protect, lock bits, access control)
- Secure Boot configuration and any bypass indicators detected
- UEFI variable anomalies (unauthorized keys, modified db/dbx, MOK enrollment)
- ESP contents inventory with hash verification against known-good baselines
- Firmware module comparison against vendor whitelist (added, modified, removed)
- Known bootkit family attribution with confidence level
- Boot chain integrity verification results for each component
- Remediation steps (reflash, key rotation, hardware replacement)
- MITRE ATT&CK mapping (T1542.001 - System Firmware, T1542.003 - Bootkit)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **UEFI Bootkit** | Malware that persists in UEFI firmware or boot process, executing before operating system loads and surviving OS reinstallation |
| **SPI Flash** | Serial Peripheral Interface flash memory chip on motherboard storing UEFI firmware; firmware-level bootkits like LoJax and MoonBounce modify SPI flash contents |
| **EFI System Partition (ESP)** | FAT32 partition containing EFI bootloaders and drivers; bootkits like BlackLotus and ESPecter modify files on ESP for persistence |
| **Secure Boot** | UEFI security feature that verifies digital signatures of boot components; can be bypassed via vulnerabilities (CVE-2022-21894) or MOK enrollment |
| **DXE Driver** | Driver Execution Environment driver loaded during UEFI boot; firmware implants inject malicious DXE drivers that execute before OS |
| **Machine Owner Key (MOK)** | User-installable Secure Boot key; BlackLotus enrolls attacker-controlled MOKs to sign malicious bootloaders |
| **chipsec** | Intel platform security assessment framework for analyzing SPI flash, UEFI variables, Secure Boot, and hardware security configurations |
| **HVCI** | Hypervisor-enforced Code Integrity, Windows security feature that bootkits disable to load unsigned kernel drivers |

## Tools & Systems

- **chipsec**: Intel framework for dumping SPI flash, reading UEFI variables, verifying firmware write protection, and Secure Boot configuration auditing
- **UEFITool**: Open-source UEFI firmware image parser for inspecting firmware volumes, extracting DXE drivers, and comparing module GUIDs
- **sigcheck**: Sysinternals utility for verifying digital signatures of EFI binaries and boot chain components
- **flashrom**: Open-source SPI flash programmer for reading and writing firmware chips on supported platforms
- **YARA**: Pattern matching engine used with UEFI-specific rule sets to detect known bootkit signatures in firmware dumps

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-uefi-bootkit-persistence
