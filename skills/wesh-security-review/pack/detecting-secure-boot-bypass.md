---
name: detecting-secure-boot-bypass
description: Detect UEFI Secure Boot bypasses and bootkits such as BlackLotus and Bootkitty by verifying Secure Boot state, checking dbx revocation currency, and hashing EFI boot binaries against known-bad sets using mokutil, efi-readvar/dbxtool, CHIPSEC, sbverify/pesign, and Windows Confirm-SecureBootUEFI.
subdomain: hardware-firmware-security
facing: defense
mitre_attack:
- T1542.003
nist_csf:
- DE.CM-01
upstream: detecting-secure-boot-bypass@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Root/administrator on target (firmware reads require privilege).
- Linux tooling:
  ```bash
  sudo apt install mokutil efitools sbsigntool dbxtool      # Debian/Ubuntu
  sudo dnf install mokutil efitools sbsigntools dbxtool     # Fedora/RHEL
  ```
- CHIPSEC (run from live USB or controlled host; loads kernel driver):
  ```bash
  pip install chipsec        # or build from https://github.com/chipsec/chipsec
  ```
- Windows tooling: PowerShell (built-in `Confirm-SecureBootUEFI`, `Get-SecureBootUEFI`), and optionally UEFI dbx update package from Microsoft.
- Current `dbxupdate` files from https://uefi.org/revocationlistfile to compare against.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1542.003 | Pre-OS Boot: Bootkit | Core technique — bootkit subverts boot chain below OS. |
| T1542 | Pre-OS Boot | Parent technique covering firmware/boot-component tampering. |
| T1542.001 | Pre-OS Boot: System Firmware | Adjacent: firmware modification used to persist or weaken Secure Boot. |
| T1014 | Rootkit | Bootkits provide rootkit-level concealment and persistence. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | BlackLotus disables BitLocker/HVCI/Defender after bypassing Secure Boot. |

## Workflow

### 1. Confirm Secure Boot state (Linux)
Disabled or setup-mode platform offers no protection.
```bash
mokutil --sb-state                       # "SecureBoot enabled" expected
bootctl status | grep -i "secure boot"   # systemd-boot view
# 6 = enabled+user mode on the EFI SecureBoot/SetupMode vars:
od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
```

### 2. Confirm Secure Boot state (Windows)
```powershell
Confirm-SecureBootUEFI        # $true if enabled
# Inspect the raw dbx variable from Windows:
[System.BitConverter]::ToString((Get-SecureBootUEFI dbx).bytes) | Out-File dbx.hex
```

### 3. Enumerate Secure Boot databases
List db (allowed), dbx (revoked), KEK, and PK.
```bash
efi-readvar                      # dumps PK, KEK, db, dbx
efi-readvar -v dbx -o dbx.esl    # export dbx to a file for offline analysis
mokutil --list-enrolled          # MOK (shim) enrolled keys
mokutil --db                     # platform db entries via shim
```

### 4. Assess dbx freshness and applied revocations
Compare on-system dbx to current official UEFI revocation list.
```bash
dbxtool --list                                   # current dbx entries + count
# Download latest dbxupdate from uefi.org/revocationlistfile, then:
dbxtool --dbx ./DBXUpdate.bin --apply --dry-run  # show what WOULD be added (no write)
```
Low dbx entry count or absence of recent revocations indicates platform is behind and likely still vulnerable to known bypasses.

### 5. Check Secure Boot variable protection with CHIPSEC
Verify SB key variables are authenticated and not freely writable.
```bash
# Verify Secure Boot is enabled and the SB variables are properly protected:
sudo chipsec_main -m common.secureboot.variables
# Check S3 resume boot-script protections (an SMM/firmware bypass vector):
sudo chipsec_main -m common.uefi.s3bootscript
# Dump SPI flash for offline firmware diffing:
sudo chipsec_util spi dump rom.bin
```

### 6. Hash ESP boot binaries and check signatures
Verify bootloaders are signed and not present in dbx.
```bash
# Locate and hash EFI boot binaries
find /boot/efi -iname '*.efi' -exec sha256sum {} \;
# Validate a binary's signature against the platform db
sbverify --list /boot/efi/EFI/BOOT/bootx64.efi
sbverify --cert /etc/secureboot/db.crt /boot/efi/EFI/Microsoft/Boot/bootmgfw.efi
# pesign equivalent on RHEL-family:
pesign -S -i /boot/efi/EFI/BOOT/bootx64.efi
```

### 7. Cross-check against known-bad bootkit hashes
Compare collected hashes to revocation/known-bad sets (e.g., LoFP / vendor advisories).
```bash
# Example: confirm a binary's SHA-256 is NOT one of the revoked CVE-2022-21894 boot managers
sha256sum /boot/efi/EFI/Microsoft/Boot/bootmgfw.efi
# Compare against the hash list extracted from the latest dbxupdate / advisory.
```

### 8. Inspect for bootkit artifacts
Look for unauthorized ESP modifications and self-deployment markers.
```bash
# Unexpected files / recently modified binaries on the ESP
ls -laR /boot/efi/EFI/
find /boot/efi -newermt "-30 days" -iname '*.efi'
# On Windows, examine the EFI partition for rogue \EFI\Microsoft\Boot entries.
```

### 9. Validate measured-boot evidence (optional pivot)
If TPM is present, current PCR[7] reflects Secure Boot policy; deviations corroborate tampering.
```bash
tpm2_pcrread sha256:7        # Secure Boot policy PCR
```

### 10. Run bundled assessment helper
`agent.py` collects SB state, dbx counts, ESP binary hashes, and CHIPSEC results into one report.
```bash
sudo python scripts/agent.py --check-chipsec --output secureboot_report.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| mokutil | Secure Boot state and enrolled keys (Linux) | https://github.com/lcp/mokutil |
| efitools (efi-readvar) | Dump PK/KEK/db/dbx | https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git |
| dbxtool | Inspect and apply dbx updates | https://github.com/rhboot/dbxtool |
| CHIPSEC | Firmware / Secure Boot variable assessment | https://github.com/chipsec/chipsec |
| sbsigntool / pesign | EFI binary signature verification | https://github.com/jejb/sbsigntools |
| UEFI Revocation List | Official dbx update files | https://uefi.org/revocationlistfile |
| Microsoft KB CVE-2023-24932 | Secure Boot bypass guidance | https://support.microsoft.com/topic/kb5025885 |
| ESET BlackLotus analysis | Bootkit technical writeup | https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/ |

## Validation Criteria

- [ ] Secure Boot confirmed enabled and in user mode on target.
- [ ] PK/KEK/db/dbx enumerated and exported for analysis.
- [ ] dbx compared against current official UEFI revocation list.
- [ ] CVE-2022-21894 / CVE-2023-24932 revocations confirmed present (or gap flagged).
- [ ] CHIPSEC `secureboot.variables` and `s3bootscript` modules run.
- [ ] ESP boot binaries hashed and signature-verified.
- [ ] Hashes cross-checked against known-bad / revoked sets.
- [ ] ESP inspected for unauthorized or recently modified binaries.
- [ ] Findings documented with remediation (dbx update / firmware update) per host.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-secure-boot-bypass
