---
name: performing-disk-forensics-investigation
description: Conduct disk forensics investigations using forensic imaging, file system analysis, and timeline reconstruction, with tools such as FTK Imager, Autopsy, and The Sleuth Kit, for evidence acquisition, deleted file recovery, and artifact examination.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1490
- T1070
- T1078
- T1005
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: performing-disk-forensics-investigation@54a7988 Apache-2.0, modified by wesh
---
Not for: volatile evidence (running processes, network connections); use memory forensics with Volatility instead.

## Prerequisites

- Forensic workstation with write-blocking hardware or software (Tableau T35u, Arsenal Image Mounter)
- Forensic imaging software: FTK Imager, Guymager, or dd with dcfldd
- Analysis platform: Autopsy, FTK (Forensic Toolkit), or X-Ways Forensics
- Sufficient storage (2-3x target drive size for image plus working copies)
- Chain of custody forms and evidence bags for physical media
- Hash verification tools for evidence integrity (SHA-256)

## Workflow

### Step 1: Secure and Document Evidence

Before touching any storage media, establish chain of custody:

- Photograph system, noting serial numbers, labels, and cable connections
- Document evidence source: device type, make, model, serial number, capacity
- Complete chain of custody form with date, time, handler name, and reason for acquisition
- Use hardware write blocker when connecting evidence drive to forensic workstation

```
Chain of Custody Record:
━━━━━━━━━━━━━━━━━━━━━━━
Case ID:          INC-2025-1547
Evidence ID:      EVD-001
Description:      Samsung 870 EVO 500GB SSD
Serial Number:    S5XXNJ0R912345
Source Host:      WKSTN-042
Acquired By:      [Analyst Name]
Date/Time:        2025-11-15T16:30:00Z
Write Blocker:    Tableau T35u (S/N: T35U-12345)
```

### Step 2: Create Forensic Image

Produce bit-for-bit copy of evidence drive:

**Using FTK Imager (Windows):**
1. Connect evidence drive through write blocker
2. File > Create Disk Image > Select source drive
3. Choose E01 (Expert Witness Format) for compression and metadata
4. Set destination path and evidence item information
5. Enable "Verify images after they are created"
6. Record source and image hash values

**Using dcfldd (Linux):**
```bash
# Create raw image with hash verification
dcfldd if=/dev/sdb of=/evidence/WKSTN-042.dd \
  hash=sha256 hashlog=/evidence/WKSTN-042.sha256 \
  bs=4096 conv=noerror,sync
# Verify image integrity
sha256sum /evidence/WKSTN-042.dd
```

```
Imaging Summary:
Source Drive:    /dev/sdb (Samsung 870 EVO 500GB)
Image File:     WKSTN-042.E01
Image Format:   E01 (Expert Witness)
Source Hash:     SHA-256: a1b2c3d4e5f6...
Image Hash:      SHA-256: a1b2c3d4e5f6...  (MATCH)
Sectors Read:    976,773,168
Errors:          0
Duration:        47 minutes
```

### Step 3: Analyze File System Structure

Open forensic image in Autopsy or FTK and examine file system:

- Identify partition layout (MBR/GPT, NTFS/ext4/APFS partitions)
- Examine Master File Table (MFT) for NTFS or inode tables for ext4
- Identify deleted files and directories (marked as unallocated but not yet overwritten)
- Recover files from unallocated space using file carving
- Examine alternate data streams (NTFS ADS) for hidden data

**Key Windows Artifacts to Examine:**
```
User Activity:
- NTUSER.DAT (registry hive per user)
- UsrClass.dat (shellbags, file access history)
- Recent files: %AppData%\Microsoft\Windows\Recent\
- Jump lists: %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\
Program Execution:
- Prefetch: C:\Windows\Prefetch\*.pf
- Amcache: C:\Windows\appcompat\Programs\Amcache.hve
- SRUM: C:\Windows\System32\SRU\SRUDB.dat
- ShimCache: SYSTEM registry hive
Persistence:
- Scheduled Tasks: C:\Windows\System32\Tasks\
- Startup folders: %AppData%\Microsoft\Windows\Start Menu\Programs\Startup\
- Services: SYSTEM registry hive
Network:
- WLAN profiles: C:\ProgramData\Microsoft\Wlansvc\Profiles\
- Browser history: Chrome, Firefox, Edge profile directories
```

### Step 4: Reconstruct Timeline

Build comprehensive timeline of file system activity:

**Using Autopsy Timeline Module:**
1. Generate timeline from all available sources (MFT, event logs, browser history, prefetch)
2. Filter to investigation timeframe
3. Identify clusters of activity correlating with incident
4. Document sequence of attacker actions based on file creation, modification, and access timestamps

**Using Sleuth Kit (command line):**
```bash
# Generate body file from NTFS image
fls -r -m / WKSTN-042.dd > bodyfile.txt
# Create timeline from body file
mactime -b bodyfile.txt -d > timeline.csv
# Filter timeline to investigation period
grep "2025-11-15" timeline.csv | sort > incident_timeline.csv
```

### Step 5: Recover and Analyze Artifacts

Extract and analyze specific forensic artifacts:

- **Prefetch files**: Parse with PECmd to determine program execution times and loaded DLLs
- **Event logs**: Parse with EvtxECmd for Windows XML Event Logs
- **Registry**: Parse with RegRipper or Registry Explorer for user activity and system configuration
- **Browser artifacts**: Parse with Hindsight (Chrome), KAPE, or DB Browser for SQLite databases
- **USB device history**: Extract from SYSTEM\CurrentControlSet\Enum\USBSTOR registry key
- **$MFT analysis**: Parse with MFTECmd for detailed file metadata including $SI and $FN timestamps

### Step 6: Document Findings

Compile forensic analysis report suitable for legal proceedings:

- Maintain evidence integrity documentation (hash chain)
- Document every tool used and its version
- Record all analysis steps in reproducible manner
- Present findings factually without conjecture
- Clearly distinguish between facts (observed data) and interpretations (analyst conclusions)

## Key Concepts

| Term | Definition |
|------|------------|
| **Forensic Image** | Bit-for-bit copy of storage media that preserves all data including deleted files and unallocated space |
| **Write Blocker** | Hardware or software device that prevents any modification to evidence media during acquisition |
| **E01 Format** | Expert Witness Format used by EnCase and FTK; supports compression, metadata, and built-in hash verification |
| **File Carving** | Recovery technique that searches unallocated disk space for file headers and footers to reconstruct deleted files |
| **MFT (Master File Table)** | NTFS metadata structure containing entries for every file and directory, including deleted entries |
| **MAC Timestamps** | Modified, Accessed, Created timestamps on files used for timeline reconstruction (NTFS also has Entry Modified) |
| **Prefetch** | Windows artifact recording program execution metadata; contains execution count, timestamps, and loaded DLLs |
| **Unallocated Space** | Disk sectors not assigned to any file; may contain remnants of deleted files recoverable through carving |

## Tools & Systems

- **FTK Imager**: Free forensic imaging tool supporting E01, AFF, and raw formats with built-in hash verification
- **Autopsy**: Open-source digital forensics platform built on Sleuth Kit for comprehensive disk analysis
- **KAPE (Kroll Artifact Parser and Extractor)**: Triage collection and parsing tool for rapid artifact extraction
- **X-Ways Forensics**: Commercial forensic analysis tool known for speed and efficiency on large datasets
- **Eric Zimmerman's Tools**: Suite of free forensic parsers (PECmd, MFTECmd, EvtxECmd, RegRipper) for Windows artifacts

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-disk-forensics-investigation
