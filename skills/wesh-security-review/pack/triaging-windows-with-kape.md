---
name: triaging-windows-with-kape
description: Runs KAPE (Kroll Artifact Parser and Extractor) to collect targeted forensic artifacts (registry hives, $MFT, event logs, prefetch, browser data) via Targets and parse them with Modules wrapping Eric Zimmerman's EZ Tools (PECmd, MFTECmd, RECmd).
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
nist_csf:
- RS.AN-03
upstream: triaging-windows-with-kape@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** KAPE collects forensic artifacts from systems. Only run KAPE against systems you own or are explicitly authorized in writing to acquire and analyze. Preserve chain of custody and follow your organization's evidence-handling procedures.

## Prerequisites

- Windows host (KAPE runs on Windows; EZ Tools modules require the .NET runtime bundled with tools).
- Download KAPE from official source (free, registration required): https://www.kroll.com/kape
- Administrator privileges (required for raw volume access and VSS).
- Update Targets, Modules, and bundled binaries:
  ```cmd
  REM From the KAPE directory, sync community Targets/Modules from GitHub
  kape.exe --sync
  REM Download/update the EZ Tools binaries that Modules invoke
  Get-KAPEUpdate.ps1
  ```
- Clean, write-protected destination (external drive or network share) separate from evidence source.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1005 | Data from Local System | KAPE reads artifacts directly from local file system; defenders use same capability to forensically acquire that data for analysis. |

KAPE is defensive DFIR tool. mapping reflects data-source artifacts (local file system) that adversary actions leave behind and that KAPE preserves for investigation.

## Workflow

### 1. Sync configurations and update binaries
Always work from current Targets/Modules and EZ Tools binaries so parsers match latest artifact formats.
```cmd
cd C:\KAPE
kape.exe --sync
```

### 2. Inventory available Targets and Modules
List what is available before building collection so you scope precisely.
```cmd
REM Show all Targets
kape.exe --tlist
REM Show all Modules
kape.exe --mlist
```

### 3. Collect triage target set
Targets require three switches `--tsource`, `--target`, and `--tdest`. `--tflush` clears destination first. Use compound target e.g. `KapeTriage` for fast, broad pull.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --tflush
```

### 4. Include Volume Shadow Copies
Add `--vss` to also process every VSS snapshot on source volume, recovering historical artifact states.
```cmd
kape.exe --tsource C: ^
         --target !SANS_Triage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --vss --tflush
```

### 5. Package collection as container with hashing
`--vhdx` (or `--zip`) wraps output into single mountable/transportable container. `--vhdx` takes base name (identifier), NOT filename. KAPE writes console log and copy log you should retain.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --vhdx HOST01 --tflush --gui
```

### 6. Process collection with Modules
Modules require `--module` and `--mdest`. Point `--msource` at collected target output and run `!EZParser` to parse everything into CSV/JSON.
```cmd
kape.exe --msource E:\kape_out\HOST01\tdest\C ^
         --mdest E:\kape_out\HOST01\mdest ^
         --module !EZParser ^
         --mflush
```

### 7. One-shot collect + parse
You can collect and process in single invocation by supplying both Target and Module switches.
```cmd
kape.exe --tsource C: ^
         --target KapeTriage ^
         --tdest E:\kape_out\HOST01\tdest ^
         --mdest E:\kape_out\HOST01\mdest ^
         --module !EZParser ^
         --tflush --mflush --vss
```

### 8. Build batch-mode `_kape.cli` for fleet deployment
KAPE reads a `_kape.cli` file (one argument set per line) placed next to `kape.exe` and executes each line in sequence — ideal for pushing identical collection via EDR/PSExec. Generate exact CLI from GUI's "Copy command line" button, then drop it into `_kape.cli`.
```cmd
REM Contents of _kape.cli (each line = one full KAPE run):
--tsource C: --target KapeTriage --tdest %%d\Disk\%%m --vhdx %%m --zv false
```
`%%d` resolves to KAPE directory and `%%m` to machine name, so single CLI auto-names output per host. Launch by running `kape.exe` with no arguments.

### 9. Verify integrity
Confirm KAPE's `CopyLog`, `ConsoleLog`, and `SkipLog` CSVs are present in target output, and validate SHA-1 hashes KAPE records for each copied file against source where possible.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| KAPE download | Official Kroll distribution (free) | https://www.kroll.com/kape |
| KAPE Documentation | MDwiki docs for switches and config | https://ericzimmerman.github.io/KapeDocs/ |
| KapeFiles repo | Community Targets and Modules | https://github.com/EricZimmerman/KapeFiles |
| EZ Tools | Parsers invoked by KAPE Modules | https://ericzimmerman.github.io/ |
| KAPE on SANS | Background, history, methodology | https://www.sans.org/tools/kape/ |

## Key Switches

| Switch | Phase | Purpose |
|--------|-------|---------|
| `--tsource` | Target | Source volume/drive to collect from |
| `--target` | Target | Target or compound target name |
| `--tdest` | Target | Destination for collected files |
| `--tflush` | Target | Empty `--tdest` before collecting |
| `--vss` | Target | Process all Volume Shadow Copies |
| `--vhdx` / `--zip` | Target | Package output into container (base name) |
| `--module` | Module | Module or compound module name |
| `--msource` | Module | Source data for module processing |
| `--mdest` | Module | Destination for parsed output |
| `--mflush` | Module | Empty `--mdest` before processing |
| `--sync` | Both | Update Targets/Modules from GitHub |
| `--tlist` / `--mlist` | Both | List available Targets / Modules |

## Validation Criteria

- [ ] KAPE Targets/Modules and EZ Tools binaries synced to current versions
- [ ] Triage target collected with `--tsource`, `--target`, `--tdest`
- [ ] Volume Shadow Copies included where historical state is needed
- [ ] Output packaged as VHDX or ZIP for transport/chain of custody
- [ ] CopyLog/ConsoleLog/SkipLog present and reviewed
- [ ] Modules run (`!EZParser`) producing CSV/JSON in `--mdest`
- [ ] File hashes recorded and verified against source
- [ ] Batch `_kape.cli` validated for fleet deployment where applicable

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/triaging-windows-with-kape
