---
name: analyzing-malicious-pdf-with-peepdf
description: Perform static analysis of malicious PDF documents using peepdf, pdfid, and pdf-parser to extract embedded JavaScript, shellcode, and suspicious objects.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1204.002
- T1059.007
- T1027
- T1106
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: analyzing-malicious-pdf-with-peepdf@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.8+ with peepdf-3 installed (pip install peepdf-3)
- pdfid.py and pdf-parser.py from Didier Stevens suite
- Isolated analysis environment (VM or sandbox)
- Optional: PyV8 for JavaScript emulation within peepdf
- Optional: Pylibemu for shellcode analysis

## Workflow

1. **Triage with pdfid**: Scan PDF for suspicious keywords (/JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile).
2. **Interactive Analysis**: Open PDF in peepdf interactive mode to explore object structure.
3. **Identify Suspicious Objects**: Locate objects containing JavaScript, streams, or encoded data.
4. **Extract Content**: Dump suspicious streams and decode filters (FlateDecode, ASCIIHexDecode).
5. **Deobfuscate JavaScript**: Analyze extracted JS for shellcode, heap sprays, or exploit code.
6. **Check VirusTotal**: Use peepdf vtcheck to cross-reference file hash with AV detections.
7. **Generate IOCs**: Extract URLs, domains, hashes, and shellcode signatures.

## Key Concepts

| Concept | Description |
|---------|-------------|
| /OpenAction | Automatic action executed when PDF is opened |
| /JavaScript /JS | Embedded JavaScript code in PDF objects |
| /Launch | Action that launches external applications |
| /EmbeddedFile | File embedded within PDF structure |
| FlateDecode | zlib compression filter used to hide content |
| Object Streams | PDF objects stored in compressed streams |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| peepdf / peepdf-3 | Interactive PDF analysis with JS emulation |
| pdfid.py | Quick triage scanning for suspicious keywords |
| pdf-parser.py | Deep object-level PDF parsing |
| VirusTotal | Hash lookup and AV detection cross-reference |
| CyberChef | Decode and transform extracted payloads |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-malicious-pdf-with-peepdf
