---
name: implementing-log-integrity-with-blockchain
description: Builds an append-only log integrity chain using SHA-256 hash chaining, where each entry incorporates the previous entry's hash so tampering invalidates all subsequent hashes; covers log ingestion (syslog/JSON/plain text), chain verification, pinpoint tamper detection, and checkpoint anchoring to external timestamping services.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-log-integrity-with-blockchain@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with security operations concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Ingest log entries from syslog, JSON, or plain text files.
3. For each entry, compute SHA-256 hash of: previous_hash + timestamp + log_content.
4. Store chain as JSON ledger with entry index, timestamp, content hash, previous hash, and chain hash.
5. Verify chain integrity by recomputing all hashes and detecting breaks.
6. Optionally anchor checkpoint hashes to external timestamping service.

```bash
python scripts/agent.py --log-file /var/log/syslog --chain-file log_chain.json --verify --output integrity_report.json
```

## Examples

### Chain Entry Structure
```json
{"index": 42, "timestamp": "2024-01-15T10:30:00Z", "content_hash": "a1b2c3...",
 "prev_hash": "d4e5f6...", "chain_hash": "SHA256(prev_hash + timestamp + content_hash)"}
```

### Tamper Detection
If entry 42 is modified, chain_hash[42] will not match SHA256(chain_hash[41] + ...), and all entries from 42 onward will be flagged as invalid.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-log-integrity-with-blockchain
