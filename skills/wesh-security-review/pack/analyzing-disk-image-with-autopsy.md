---
name: analyzing-disk-image-with-autopsy
description: Perform comprehensive forensic analysis of raw (dd), E01, or AFF disk images with Autopsy and The Sleuth Kit, recovering deleted files, examining metadata and embedded artifacts, keyword searching, and building investigation timelines with visual reports.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
- T1074.001
- T1070.004
- T1083
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: analyzing-disk-image-with-autopsy@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- Autopsy 4.x installed (Windows) or Autopsy 4.x with Sleuth Kit (Linux)
- Forensic disk image in raw (dd), E01 (EnCase), or AFF format
- Minimum 8GB RAM (16GB recommended for large images)
- Java Runtime Environment (JRE) 8+ for Autopsy
- Sufficient disk space for Autopsy case database (2-3x image size)
- Hash databases (NSRL, known-bad hashes) for file identification

## Workflow

### Step 1: Install Autopsy and Configure Environment

```bash
# On Linux, install Sleuth Kit and Autopsy
sudo apt-get install autopsy sleuthkit
# Download Autopsy 4.x (GUI version) from official source
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip -d /opt/autopsy
# On Windows, run the MSI installer from sleuthkit.org
# Launch Autopsy
/opt/autopsy/bin/autopsy --nosplash
# For Sleuth Kit command-line analysis alongside Autopsy
sudo apt-get install sleuthkit
```

### Step 2: Create New Case and Add Disk Image

```
1. Launch Autopsy > "New Case"
2. Enter Case Name: "CASE-2024-001-Workstation"
3. Set Base Directory: /cases/case-2024-001/autopsy/
4. Enter Case Number, Examiner Name
5. Click "Add Data Source"
6. Select "Disk Image or VM File"
7. Browse to: /cases/case-2024-001/images/evidence.dd
8. Select Time Zone of the original system
9. Configure Ingest Modules (see Step 3)
```

```bash
# Alternatively, use Sleuth Kit CLI to verify the image first
img_stat /cases/case-2024-001/images/evidence.dd
# List partitions in the image
mmls /cases/case-2024-001/images/evidence.dd
# Output example:
# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#      Slot    Start        End          Length       Description
#      00:  -----   0000000000   0000002047   0000002048   Primary Table (#0)
#      01:  00:00   0000002048   0001026047   0001024000   NTFS (0x07)
#      02:  00:01   0001026048   0976771071   0975745024   NTFS (0x07)
# List files in a partition (offset 2048 sectors)
fls -o 2048 /cases/case-2024-001/images/evidence.dd
```

### Step 3: Configure and Run Ingest Modules

```
Enable the following Autopsy Ingest Modules:
- Recent Activity: Extracts browser history, downloads, cookies, bookmarks
- Hash Lookup: Compares files against NSRL and known-bad hash sets
- File Type Identification: Identifies files by signature, not extension
- Keyword Search: Indexes content for full-text searching
- Email Parser: Extracts emails from PST, MBOX, EML files
- Extension Mismatch Detector: Finds files with wrong extensions
- Exif Parser: Extracts metadata from images (GPS, camera, timestamps)
- Encryption Detection: Identifies encrypted files and containers
- Interesting Files Identifier: Flags files matching custom rule sets
- Embedded File Extractor: Extracts files from ZIP, Office docs, PDFs
- Picture Analyzer: Categorizes images using PhotoDNA or hash matching
- Data Source Integrity: Verifies image hash during ingest
```

```bash
# Configure NSRL hash set for known-good filtering
# Download NSRL from https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
wget https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
unzip rds_modernm.zip -d /opt/autopsy/hashsets/
# Import into Autopsy:
# Tools > Options > Hash Sets > Import > Select NSRLFile.txt
# Mark as "Known" (to filter out known-good files)
```

### Step 4: Analyze File System and Recover Deleted Files

```bash
# In Autopsy GUI: Navigate tree structure
# - Data Sources > evidence.dd > vol2 (NTFS)
# - Examine directory tree, note deleted files (marked with X)
# Using Sleuth Kit CLI for targeted recovery
# List deleted files
fls -rd -o 2048 /cases/case-2024-001/images/evidence.dd
# Recover a specific deleted file by inode
icat -o 2048 /cases/case-2024-001/images/evidence.dd 14523 > /cases/case-2024-001/recovered/deleted_document.docx
# Extract all files from a directory
tsk_recover -o 2048 -d /Users/suspect/Documents \
   /cases/case-2024-001/images/evidence.dd \
   /cases/case-2024-001/recovered/documents/
# Get detailed file metadata
istat -o 2048 /cases/case-2024-001/images/evidence.dd 14523
# Shows: creation, modification, access, MFT change timestamps, size, data runs
```

### Step 5: Perform Keyword Searches and Tag Evidence

```
In Autopsy:
1. Keyword Search panel > "Ad Hoc Keyword Search"
2. Search terms: credit card patterns, SSN regex, email addresses
3. Example regex for credit cards: \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b
4. Example regex for SSN: \b\d{3}-\d{2}-\d{4}\b
5. Review results > Right-click items > "Add Tag"
6. Create tags: "Evidence-Critical", "Evidence-Supporting", "Requires-Review"
7. Add comments to tagged items documenting relevance
```

```bash
# Using Sleuth Kit for CLI keyword search
srch_strings -a -o 2048 /cases/case-2024-001/images/evidence.dd | \
   grep -iE '(password|secret|confidential)' > /cases/case-2024-001/keyword_hits.txt
# Search for specific file signatures
sigfind -o 2048 /cases/case-2024-001/images/evidence.dd 25504446
# 25504446 = %PDF header signature
```

### Step 6: Build Timeline and Generate Reports

```
In Autopsy:
1. Timeline viewer: Tools > Timeline
2. Select date range of interest (incident window)
3. Filter by event type: File Created, Modified, Accessed, Web Activity
4. Zoom into suspicious time periods
5. Export timeline events as CSV for external analysis
Generate Report:
1. Generate Report > HTML Report
2. Select tagged items and data sources to include
3. Configure report sections: file listings, keyword hits, timeline
4. Export to /cases/case-2024-001/reports/
```

```bash
# Using Sleuth Kit mactime for CLI timeline
fls -r -m "/" -o 2048 /cases/case-2024-001/images/evidence.dd > /cases/case-2024-001/bodyfile.txt
# Generate timeline from bodyfile
mactime -b /cases/case-2024-001/bodyfile.txt -d > /cases/case-2024-001/timeline.csv
# Filter timeline to specific date range
mactime -b /cases/case-2024-001/bodyfile.txt \
   -d 2024-01-15..2024-01-20 > /cases/case-2024-001/incident_timeline.csv
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Ingest Modules | Automated analysis plugins that process data sources upon import |
| MFT (Master File Table) | NTFS metadata structure recording all file entries and attributes |
| File carving | Recovering files from unallocated space using file signatures |
| Hash filtering | Using NSRL or custom hash sets to exclude known-good or flag known-bad files |
| Timeline analysis | Chronological reconstruction of file system and user activity events |
| Deleted file recovery | Restoring files whose directory entries are removed but data remains |
| Keyword indexing | Full-text search index built from all file content including slack space |
| Artifact extraction | Automated parsing of browser, email, registry, and OS-specific artifacts |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Autopsy | Open-source GUI forensic platform for disk image analysis |
| Sleuth Kit (TSK) | Command-line forensic toolkit underlying Autopsy |
| fls | List files and directories in disk image including deleted entries |
| icat | Extract file content by inode number from disk image |
| mactime | Generate timeline from TSK bodyfile format |
| mmls | Display partition layout of disk image |
| NSRL | NIST hash database for identifying known software files |
| sigfind | Search for file signatures at sector level |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-disk-image-with-autopsy
