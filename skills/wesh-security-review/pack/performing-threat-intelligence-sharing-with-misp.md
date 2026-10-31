---
name: performing-threat-intelligence-sharing-with-misp
description: Uses PyMISP (the official MISP REST API library) to create events with structured IOCs (IPs, domains, hashes, URLs), enrich them with MITRE ATT&CK tags and galaxy clusters, manage sharing groups and distribution levels, search existing intelligence, and export in STIX 2.1 format.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1591
- T1592
- T1593
- T1589
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
upstream: performing-threat-intelligence-sharing-with-misp@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- MISP instance (v2.4+) with API access enabled
- Python 3.9+ with `pymisp` (`pip install pymisp`)
- MISP API key (Settings > Auth Keys)
- Understanding of MISP data model (Events, Attributes, Objects, Tags, Galaxies)
- Knowledge of TLP marking and sharing protocols

## Steps

1. Install PyMISP: `pip install pymisp`
2. Initialize `ExpandedPyMISP(url, key, ssl=True)` connection
3. Create a `MISPEvent` with info, distribution level, threat level, and analysis status
4. Add attributes via `event.add_attribute(type, value)` for IPs, domains, hashes
5. Apply TLP tags and MITRE ATT&CK technique tags
6. Publish event with `misp.publish(event)`
7. Search existing events with `misp.search(controller='events', value=..., type_attribute=...)`
8. Enable and configure threat feeds for automatic IOC ingestion
9. Export events in STIX 2.1 format for cross-platform sharing
10. Validate sharing group configuration and sync server settings

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-threat-intelligence-sharing-with-misp
