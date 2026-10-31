---
name: hunting-bootkits-in-efi-system-partition
description: Baseline the EFI System Partition and hunt malicious EFI binaries such as ESPecter, BlackLotus, Bootkitty, and Glupteba by mounting the ESP, hashing and verifying boot loaders, scanning with YARA, and flagging anomalous non-EFI files or out-of-band bootloader changes.
subdomain: hardware-firmware-security
facing: defense
mitre_attack:
- T1542.003
nist_csf:
- DE.CM-01
upstream: hunting-bootkits-in-efi-system-partition@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Administrative/root access to target host (mounting and reading ESP requires elevation)
- Linux analysis tooling — install on Debian/Ubuntu:
  ```bash
  sudo apt-get update
  sudo apt-get install -y sbsigntool pesign efitools efibootmgr binwalk yara
  pip install pefile
  ```
- `UEFITool` for inspecting firmware/binaries (download from https://github.com/LongSoft/UEFITool/releases)
- Trusted **golden baseline** of EFI binary hashes for OS/vendor versions in scope (build it once on known-clean, freshly imaged host)
- For Windows targets: WinPE or forensic boot environment, or Velociraptor with the `Windows.Forensics.UEFI` artifact

## MITRE ATT&CK Mapping

| ID | Name | Relevance |
|----|------|-----------|
| T1542.003 | Pre-OS Boot: Bootkit | Adversaries place malicious boot loaders on ESP to execute before OS and EDR, achieving stealthy, resilient persistence. This skill hunts exactly that artifact. |

## Workflow

### Step 1: Identify and mount ESP read-only
ESP is FAT32 partition, usually flagged `EF00` (GPT) or `esp,boot`. Locate it and mount read-only to preserve evidence.
```bash
# Identify the ESP (type code EF00 / "EFI System")
sudo lsblk -o NAME,FSTYPE,PARTTYPENAME,MOUNTPOINT
sudo fdisk -l | grep -i "EFI System"
# Mount the ESP read-only (replace /dev/sda1 with the identified partition)
sudo mkdir -p /mnt/esp
sudo mount -o ro,umask=077 /dev/sda1 /mnt/esp
# Confirm the canonical layout: EFI/ should be the only top-level dir
ls -la /mnt/esp
```

### Step 2: Detect anomalous top-level entries (high-fidelity hunt)
Per Rapid7/Velociraptor guidance, ESP root should contain **only** the `EFI/` directory (and possibly vendor `System Volume Information`). Anything else is suspicious.
```bash
# Any path in the ESP root NOT under EFI/ is a red flag
find /mnt/esp -maxdepth 1 -mindepth 1 ! -name 'EFI' ! -iname 'System Volume Information'
# Hunt for boot binaries dropped outside expected vendor folders
find /mnt/esp -type f \( -iname '*.efi' -o -iname '*.sys' -o -iname '*.dll' \) -printf '%p\t%s bytes\t%TY-%Tm-%Td\n'
```

### Step 3: Inventory and hash every EFI binary
Compute SHA-256 of all boot binaries for baseline comparison and threat-intel lookup.
```bash
# Recursively hash all EFI/PE binaries on the ESP
find /mnt/esp -type f \( -iname '*.efi' -o -iname '*.sys' \) -print0 \
  | xargs -0 sha256sum | tee /tmp/esp_hashes.txt
# Quick triage on the primary loaders
sha256sum /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi 2>/dev/null
sha256sum /mnt/esp/EFI/Boot/bootx64.efi 2>/dev/null
sha256sum /mnt/esp/EFI/*/grubx64.efi /mnt/esp/EFI/*/shimx64.efi 2>/dev/null
```
Submit unknown hashes to VirusTotal / LOLDrivers and Binarly catalogs to identify known-vulnerable or malicious loaders (e.g., BlackLotus-abused `bootmgfw.efi` builds).

### Step 4: Verify Secure Boot signatures on each loader
Legitimate loader is signed by Microsoft UEFI CA (Windows/shim) or distro vendor. Use `sbverify` to list/verify signatures and `pesign` for certificate chain.
```bash
# List embedded signatures on a loader
sbverify --list /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi
# Verify against the platform's db certificate (export it first)
sudo efi-readvar -v db -o /tmp/db.esl   # dump Secure Boot db
sbverify --cert /path/to/MicrosoftUEFICA.pem /mnt/esp/EFI/Boot/bootx64.efi
# Inspect the PE certificate chain
pesign -S -i /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi
```
**Unsigned** loader, loader signed by unexpected/self-signed certificate, or known-vulnerable signed binary staged by attacker (BlackLotus technique) is confirmed finding.

### Step 5: Compare against golden baseline
Diff live ESP hash inventory against trusted baseline captured from clean image of same OS/vendor build.
```bash
# Sort both inventories on the hash column and diff
awk '{print $1}' /tmp/esp_hashes.txt | sort > /tmp/live.sha256
sort baseline_esp_hashes.sha256 > /tmp/base.sha256
# Hashes present live but absent from the baseline = unexpected/new binaries
comm -23 /tmp/live.sha256 /tmp/base.sha256
```
Because bootloader changes only during legitimate updates, any new hash that does not correspond to known patch is actionable lead.

### Step 6: YARA-scan ESP binaries for bootkit signatures
Run YARA rules for known bootkits (ESPecter, BlackLotus, Bootkitty, CosmicStrand) across ESP — same approach as Velociraptor's `Windows.Detection.Yara.UEFI`.
```bash
# Scan all ESP files recursively with a bootkit ruleset
yara -r -w bootkit_rules.yar /mnt/esp/
# Example: scan only the binaries collected in Step 3
yara -r bootkit_rules.yar /mnt/esp/EFI/
```
Source rules from YARA-Rules project, Eclypsium/Binarly publications, and ESET's bootkit reports.

### Step 7: Inspect and validate UEFI boot entries
ESPecter-class bootkits manipulate boot order/entries. Enumerate NVRAM boot variables and confirm each points to expected, signed loader.
```bash
# List boot entries and the current order (Bootkitty/ESPecter tamper here)
sudo efibootmgr -v
# Confirm Secure Boot is enabled and look for revoked hashes in dbx
mokutil --sb-state
sudo efi-readvar -v dbx -o /tmp/dbx.esl
```
Boot entry referencing file outside `\EFI\` or loader whose hash appears in `dbx` (revoked) but is still present indicates tampering.

### Step 8: Validate measured boot against TPM PCRs (where available)
Measured boot records boot-chain components into TPM PCRs (notably PCR 0, 2, 4). bootkit that alters loaders changes these measurements.
```bash
# Read PCRs that cover firmware and the boot loader
sudo tpm2_pcrread sha256:0,2,4,7
# Parse the TCG event log to see what was measured into each PCR
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
```
Compare measured values against host's known-good attestation baseline; unexplained PCR 4 change correlates with modified boot loader.

### Step 9: Document findings and preserve evidence
```bash
# Make a forensic image of the ESP for offline analysis before remediation
sudo dd if=/dev/sda1 of=/evidence/esp_$(hostname)_$(date +%F).img bs=4M conv=noerror,sync
sha256sum /evidence/esp_*.img > /evidence/esp_image.sha256
sudo umount /mnt/esp
```
Record every anomalous binary (path, hash, signature status, baseline diff result, YARA match) in case file before any cleanup.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| sbsigntool (`sbverify`) | List/verify Secure Boot signatures on EFI binaries | https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git |
| pesign | Inspect PE/COFF signatures and certificate chains | https://github.com/rhboot/pesign |
| efitools (`efi-readvar`) | Dump Secure Boot variables (db/dbx/KEK/PK) | https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git |
| efibootmgr / mokutil | Enumerate boot entries and Secure Boot state | https://github.com/rhboot/efibootmgr |
| UEFITool | Parse and inspect UEFI binaries/firmware | https://github.com/LongSoft/UEFITool |
| YARA | Signature-scan ESP binaries for bootkits | https://github.com/VirusTotal/yara |
| tpm2-tools | Read PCRs and TCG event log for measured boot | https://github.com/tpm2-software/tpm2-tools |
| Velociraptor `Windows.Forensics.UEFI` | Scale ESP hunting across fleet | https://docs.velociraptor.app/ |
| Eclypsium bootkit research | Threat context and detection methodology | https://eclypsium.com/blog/threat-detection-bootloaders-bootkits-secureboot/ |
| Rapid7 UEFI hunting blog | ESP hunting with Velociraptor artifacts | https://www.rapid7.com/blog/post/2024/02/29/how-to-hunt-for-uefi-malware-using-velociraptor/ |

## Known Bootkit Indicators

| Bootkit | ESP Artifact / Behavior | Reference |
|---------|-------------------------|-----------|
| ESPecter | Patched `bootmgfw.efi` + kernel drivers on ESP | ESET WeLiveSecurity 2021 |
| BlackLotus | Vulnerable signed `bootmgfw.efi` staged to bypass Secure Boot (CVE-2022-21894) | ESET 2023 |
| Bootkitty | Malicious EFI loader on ESP targeting Linux | ESET / Eclypsium 2024 |
| Glupteba (UEFI) | Replaces software on EFI partition | Eclypsium |
| CosmicStrand | UEFI firmware implant hooking boot chain | Eclypsium / Kaspersky |

## Validation Criteria

- [ ] ESP located and mounted read-only without modifying evidence
- [ ] Top-level ESP contents enumerated; any non-`EFI/` entries flagged
- [ ] All EFI binaries inventoried with SHA-256 hashes
- [ ] Secure Boot signatures verified on every boot loader
- [ ] Live inventory diffed against trusted golden baseline
- [ ] YARA bootkit ruleset run across ESP with no unexplained matches
- [ ] Boot entries (`efibootmgr`) validated; no references outside `\EFI\`
- [ ] Secure Boot confirmed enabled; no present binary matches a `dbx`-revoked hash
- [ ] TPM PCR 0/2/4 measurements compared to baseline (where TPM present)
- [ ] Forensic ESP image preserved and all findings documented

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-bootkits-in-efi-system-partition
