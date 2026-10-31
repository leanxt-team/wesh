---
name: validating-tpm-measured-boot-attestation
description: Verifies TPM 2.0 measured-boot integrity and remote attestation with tpm2-tools -- reading PCRs (tpm2_pcrread), replaying the boot event log, generating and checking signed quotes (tpm2_quote/tpm2_checkquote), and sealing secrets to a PCR policy.
subdomain: hardware-firmware-security
facing: defense
mitre_attack:
- T1542
nist_csf:
- PR.PS-01
upstream: validating-tpm-measured-boot-attestation@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- System with TPM 2.0 device and resource manager:
  ```bash
  sudo apt install tpm2-tools tpm2-abrmd        # Debian/Ubuntu
  sudo dnf install tpm2-tools tpm2-abrmd        # Fedora/RHEL
  ```
- Access to TPM (`/dev/tpm0` / `/dev/tpmrm0`) and kernel measurement log at `/sys/kernel/security/tpm0/binary_bios_measurements`.
- Root for reading some sysfs entries and for NV/AK operations.
- For remote attestation: verifier host and transport for quote/nonce exchange.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1542 | Pre-OS Boot | Measured boot detects pre-OS tampering this technique relies on. |
| T1542.001 | Pre-OS Boot: System Firmware | PCR 0–7 drift reveals unauthorized firmware modification. |
| T1542.003 | Pre-OS Boot: Bootkit | Bootloader/kernel measurements (PCR 8–10) expose bootkit changes. |
| T1014 | Rootkit | IMA measurements (PCR 10) and quote verification surface concealed tampering. |
| T1601.001 | Modify System Image: Patch System Image | Attestation against golden values flags unauthorized image patches. |

## Workflow

### 1. Confirm TPM is present and read its properties
```bash
tpm2_getcap properties-fixed | grep -i manufacturer
tpm2_getcap pcrs                 # list supported PCR banks (sha1, sha256, ...)
```

### 2. Read current PCR values
PCR 7 = Secure Boot policy; PCR 0–7 = firmware; PCR 8–9 = bootloader/kernel; PCR 10 = IMA.
```bash
tpm2_pcrread sha256                       # all sha256 PCRs
tpm2_pcrread sha256:0,1,2,3,4,5,6,7       # firmware + Secure Boot policy
tpm2_pcrread sha256:7                      # Secure Boot policy only
```

### 3. Replay TPM event log against live PCRs
Confirm recorded log reproduces current PCR values (authenticity check).
```bash
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > eventlog.yaml
# The YAML includes a "pcrs" section with the calculated values — compare to step 2.
# Any mismatch means the event log and the live PCRs disagree (tampering or stale log).
```

### 4. Create primary key and Attestation Key (AK)
AK signs quotes; its public part is shared with verifier out-of-band.
```bash
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -C primary.ctx -G rsa -u ak.pub -r ak.priv \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign'
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx
tpm2_readpublic -c ak.ctx -o ak.pem -f pem      # export AK public key for the verifier
```

### 5. Produce nonce-bound quote (attestor side)
Verifier supplies fresh random nonce to defeat replay.
```bash
NONCE=$(openssl rand -hex 20)
tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9 \
  -q "$NONCE" -m quote.msg -s quote.sig -o quote.pcrs -g sha256
# Send quote.msg, quote.sig, quote.pcrs (and the nonce) to the verifier.
```

### 6. Verify quote (verifier side)
Independently validate signature, nonce, and PCR digest with AK public key.
```bash
tpm2_checkquote -u ak.pem -m quote.msg -s quote.sig -f quote.pcrs \
  -q "$NONCE" -g sha256
# Exit 0 + matching PCR digest == authentic, fresh, untampered quote.
```

### 7. Build and compare against golden baseline
Compare attested PCRs to known-good values captured from trusted reference build.
```bash
# Capture golden values on a trusted reference machine:
tpm2_pcrread sha256:0,7 > golden_pcrs.txt
# On each attested host, diff the quote's PCR section against golden_pcrs.txt.
diff <(grep -A8 'sha256' quote.pcrs) golden_pcrs.txt
```

### 8. Seal secret to measured-boot policy (optional)
Bind secret so TPM only releases it when PCRs match trusted state.
```bash
tpm2_createpolicy --policy-pcr -l sha256:7 -L pcr7.policy -f pcr7.dat
echo -n "diskkey" | tpm2_create -C primary.ctx -L pcr7.policy \
  -i - -u sealed.pub -r sealed.priv
tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx
# Unseal succeeds only while PCR 7 matches the sealed policy:
tpm2_unseal -c sealed.ctx -p pcr:sha256:7
```

### 9. Inspect IMA runtime measurements (PCR 10)
If IMA is enabled, runtime measurement list extends PCR 10.
```bash
tpm2_pcrread sha256:10
head -20 /sys/kernel/security/ima/ascii_runtime_measurements
```

### 10. Run bundled attestation helper
`agent.py` reads PCRs, replays event log, optionally produces+verifies quote, and diffs baseline.
```bash
sudo python scripts/agent.py --pcrs 0,1,2,3,4,5,6,7 --baseline golden_pcrs.json --output attest.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| tpm2-tools | CLI for all TPM 2.0 operations | https://github.com/tpm2-software/tpm2-tools |
| tpm2-tss | TSS2 stack tools build on | https://github.com/tpm2-software/tpm2-tss |
| Keylime | Scalable remote attestation framework | https://github.com/keylime/keylime |
| TCG PC Client Platform Firmware Profile | PCR usage specification | https://trustedcomputinggroup.org/ |
| Linux IMA docs | Integrity Measurement Architecture | https://sourceforge.net/p/linux-ima/wiki/Home/ |
| RFC 9683 | Remote integrity verification of TPM devices | https://datatracker.ietf.org/doc/html/rfc9683 |

## Validation Criteria

- [ ] TPM 2.0 presence and supported PCR banks confirmed.
- [ ] Current PCR values read for firmware and Secure Boot policy PCRs.
- [ ] Event log replayed and confirmed to reproduce live PCR values.
- [ ] Attestation Key created and its public key exported to verifier.
- [ ] Nonce-bound quote produced and independently verified with `tpm2_checkquote`.
- [ ] Attested PCRs compared against golden baseline; drift flagged.
- [ ] (Optional) Secret sealed/unsealed against PCR policy successfully.
- [ ] IMA runtime measurements reviewed where enabled.
- [ ] Results documented per host with pass/fail and any drift evidence.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/validating-tpm-measured-boot-attestation
