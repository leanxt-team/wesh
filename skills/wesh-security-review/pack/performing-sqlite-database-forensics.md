---
name: performing-sqlite-database-forensics
description: Performs forensic analysis of SQLite databases by examining B-tree page structures, recovering deleted records from freelist pages and Write-Ahead Log (WAL) files, decoding encoded timestamps, and extracting evidence from browser history, messaging apps, and mobile device databases.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
- T1074
- T1119
- T1070
- T1059
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: performing-sqlite-database-forensics@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- DB Browser for SQLite (sqlitebrowser)
- SQLite command-line tools (sqlite3)
- Python 3.8+ with sqlite3 module
- Belkasoft Evidence Center or Axiom (commercial)
- Hex editor (HxD, 010 Editor) for manual page inspection
- Understanding of B-tree data structures

## SQLite Internal Structure

### Database Header (First 100 Bytes)

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | Magic string: "SQLite format 3\000" |
| 16 | 2 | Page size (512-65536 bytes) |
| 18 | 1 | File format write version |
| 19 | 1 | File format read version |
| 24 | 4 | File change counter |
| 28 | 4 | Database size in pages |
| 32 | 4 | First freelist trunk page number |
| 36 | 4 | Total freelist pages |
| 52 | 4 | Text encoding (1=UTF-8, 2=UTF-16le, 3=UTF-16be) |
| 96 | 4 | Version-valid-for number |

### Page Types

| Type | ID | Description |
|------|----|-------------|
| B-tree Interior | 0x05 | Internal table node |
| B-tree Leaf | 0x0D | Table leaf page containing actual records |
| Index Interior | 0x02 | Internal index node |
| Index Leaf | 0x0A | Index leaf page |
| Freelist Trunk | - | Tracks freed pages |
| Freelist Leaf | - | Freed page with recoverable data |
| Overflow | - | Continuation of large records |

## Deleted Record Recovery

### Method 1: Freelist Page Analysis

When records are deleted, SQLite may place their pages on freelist rather than overwriting them immediately.

```python
import struct
import sqlite3
import os
def analyze_freelist(db_path: str) -> dict:
    """Analyze SQLite freelist to identify pages containing deleted data."""
    with open(db_path, "rb") as f:
        # Read header
        header = f.read(100)
        page_size = struct.unpack(">H", header[16:18])[0]
        if page_size == 1:
            page_size = 65536
        first_freelist_page = struct.unpack(">I", header[32:36])[0]
        total_freelist_pages = struct.unpack(">I", header[36:40])[0]
        freelist_info = {
            "page_size": page_size,
            "first_freelist_page": first_freelist_page,
            "total_freelist_pages": total_freelist_pages,
            "trunk_pages": [],
            "leaf_pages": []
        }
        if first_freelist_page == 0:
            return freelist_info
        # Walk the freelist trunk chain
        trunk_page = first_freelist_page
        while trunk_page != 0:
            offset = (trunk_page - 1) * page_size
            f.seek(offset)
            page_data = f.read(page_size)
            next_trunk = struct.unpack(">I", page_data[0:4])[0]
            leaf_count = struct.unpack(">I", page_data[4:8])[0]
            leaves = []
            for i in range(leaf_count):
                leaf_page = struct.unpack(">I", page_data[8 + i * 4:12 + i * 4])[0]
                leaves.append(leaf_page)
            freelist_info["trunk_pages"].append({
                "page_number": trunk_page,
                "next_trunk": next_trunk,
                "leaf_count": leaf_count,
                "leaf_pages": leaves
            })
            freelist_info["leaf_pages"].extend(leaves)
            trunk_page = next_trunk
    return freelist_info
def extract_freelist_content(db_path: str, output_dir: str):
    """Extract raw content from freelist pages for analysis."""
    info = analyze_freelist(db_path)
    os.makedirs(output_dir, exist_ok=True)
    with open(db_path, "rb") as f:
        page_size = info["page_size"]
        for page_num in info["leaf_pages"]:
            offset = (page_num - 1) * page_size
            f.seek(offset)
            page_data = f.read(page_size)
            output_file = os.path.join(output_dir, f"freelist_page_{page_num}.bin")
            with open(output_file, "wb") as out:
                out.write(page_data)
    return len(info["leaf_pages"])
```

### Method 2: WAL (Write-Ahead Log) Analysis

WAL file contains pending transactions that have not yet been checkpointed back to main database.

```python
def parse_wal_header(wal_path: str) -> dict:
    """Parse SQLite WAL file header and frame inventory."""
    with open(wal_path, "rb") as f:
        header = f.read(32)
        magic = struct.unpack(">I", header[0:4])[0]
        file_format = struct.unpack(">I", header[4:8])[0]
        page_size = struct.unpack(">I", header[8:12])[0]
        checkpoint_seq = struct.unpack(">I", header[12:16])[0]
        salt1 = struct.unpack(">I", header[16:20])[0]
        salt2 = struct.unpack(">I", header[20:24])[0]
        wal_info = {
            "magic": hex(magic),
            "format": file_format,
            "page_size": page_size,
            "checkpoint_sequence": checkpoint_seq,
            "frames": []
        }
        # Parse frames (24-byte header + page_size data each)
        frame_offset = 32
        frame_num = 0
        file_size = os.path.getsize(wal_path)
        while frame_offset + 24 + page_size <= file_size:
            f.seek(frame_offset)
            frame_header = f.read(24)
            page_number = struct.unpack(">I", frame_header[0:4])[0]
            db_size_after = struct.unpack(">I", frame_header[4:8])[0]
            wal_info["frames"].append({
                "frame_number": frame_num,
                "page_number": page_number,
                "db_size_pages": db_size_after,
                "offset": frame_offset
            })
            frame_offset += 24 + page_size
            frame_num += 1
    return wal_info
```

### Method 3: Unallocated Space Within Pages

Deleted cells within active B-tree pages leave data in unallocated region between cell pointer array and cell content area.

```python
def analyze_unallocated_space(db_path: str, page_number: int) -> dict:
    """Analyze unallocated space within a specific B-tree page."""
    with open(db_path, "rb") as f:
        header = f.read(100)
        page_size = struct.unpack(">H", header[16:18])[0]
        if page_size == 1:
            page_size = 65536
        offset = (page_number - 1) * page_size
        f.seek(offset)
        page_data = f.read(page_size)
        # Parse page header (8 or 12 bytes depending on type)
        page_type = page_data[0]
        first_freeblock = struct.unpack(">H", page_data[1:3])[0]
        cell_count = struct.unpack(">H", page_data[3:5])[0]
        cell_content_offset = struct.unpack(">H", page_data[5:7])[0]
        if cell_content_offset == 0:
            cell_content_offset = 65536
        header_size = 12 if page_type in (0x02, 0x05) else 8
        cell_pointer_end = header_size + cell_count * 2
        unallocated_start = cell_pointer_end
        unallocated_end = cell_content_offset
        unallocated_size = unallocated_end - unallocated_start
        return {
            "page_number": page_number,
            "page_type": hex(page_type),
            "cell_count": cell_count,
            "unallocated_start": unallocated_start,
            "unallocated_end": unallocated_end,
            "unallocated_size": unallocated_size,
            "unallocated_data": page_data[unallocated_start:unallocated_end].hex()
        }
```

## Common Forensic Databases

| Application | Database File | Key Tables |
|------------|--------------|------------|
| Chrome | History | urls, visits, downloads, keyword_search_terms |
| Firefox | places.sqlite | moz_places, moz_historyvisits |
| Safari | History.db | history_items, history_visits |
| WhatsApp | msgstore.db | messages, chat_list |
| Signal | signal.sqlite | sms, mms |
| iMessage | sms.db | message, handle, chat |
| Android SMS | mmssms.db | sms, mms, threads |
| Skype | main.db | Messages, Conversations |

## Timestamp Decoding

```python
from datetime import datetime, timedelta
def decode_chrome_timestamp(chrome_ts: int) -> datetime:
    """Convert Chrome/WebKit timestamp to datetime (microseconds since 1601-01-01)."""
    epoch_delta = 11644473600
    return datetime.utcfromtimestamp((chrome_ts / 1000000) - epoch_delta)
def decode_unix_timestamp(unix_ts: int) -> datetime:
    """Convert Unix timestamp to datetime."""
    return datetime.utcfromtimestamp(unix_ts)
def decode_mac_absolute_time(mac_ts: float) -> datetime:
    """Convert Mac Absolute Time (seconds since 2001-01-01)."""
    mac_epoch = datetime(2001, 1, 1)
    return mac_epoch + timedelta(seconds=mac_ts)
def decode_mozilla_timestamp(moz_ts: int) -> datetime:
    """Convert Mozilla PRTime (microseconds since Unix epoch)."""
    return datetime.utcfromtimestamp(moz_ts / 1000000)
```

## References

- SQLite File Format: https://www.sqlite.org/fileformat2.html
- Belkasoft SQLite Analysis: https://belkasoft.com/sqlite-analysis
- Spyder Forensics SQLite Training: https://www.spyderforensics.com/sqlite-forensic-fundamentals-2025/
- Forensic Analysis of Damaged SQLite Databases: https://www.forensicfocus.com/articles/forensic-analysis-of-damaged-sqlite-databases/

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-sqlite-database-forensics
