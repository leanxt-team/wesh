---
name: analyzing-threat-actor-ttps-with-mitre-navigator
description: Map advanced persistent threat (APT) group TTPs to the MITRE ATT&CK framework using the attackcti Python library to query STIX/TAXII data for group-technique associations, then generate ATT&CK Navigator layer files to visualize and compare defensive coverage against adversary profiles.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1566.001
- T1059.001
- T1071.001
- T1547.001
- T1053.005
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
upstream: analyzing-threat-actor-ttps-with-mitre-navigator@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.8+ with attackcti and stix2 libraries installed
- MITRE ATT&CK Navigator (web UI or local instance)
- Understanding of STIX 2.1 objects and relationships

## Steps

1. Query ATT&CK STIX data for target threat group using attackcti
2. Extract techniques associated with group via STIX relationships
3. Generate ATT&CK Navigator layer JSON with technique annotations
4. Overlay detection coverage to identify gaps
5. Export layer for team review and defensive planning

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-threat-actor-ttps-with-mitre-navigator
