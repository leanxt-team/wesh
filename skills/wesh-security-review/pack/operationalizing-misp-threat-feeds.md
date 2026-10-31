---
name: operationalizing-misp-threat-feeds
description: Stand up MISP, enable and cache curated threat feeds (CIRCL, abuse.ch, Feodo Tracker), apply warninglists to suppress false positives, query indicators with PyMISP, and export attributes as auto-generated Suricata/Sigma/Wazuh detection rules.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1589
nist_csf:
- ID.RA-02
upstream: operationalizing-misp-threat-feeds@54a7988 Apache-2.0, modified by wesh
---
> **Note:** This skill covers defensive threat-intelligence platform. Handle ingested intelligence according to its Traffic Light Protocol (TLP) marking and your sharing agreements. Treat ingested IOCs as potentially sensitive.

## Prerequisites

- Running MISP instance (maintained container images are fastest path):
  ```bash
  git clone https://github.com/MISP/misp-docker.git
  cd misp-docker && cp template.env .env
  docker compose up -d
  # Web UI on https://localhost; default admin: admin@admin.test / admin
  ```
- A MISP **Auth Key** (UI: Administration -> List Auth Keys -> Add).
- PyMISP:
  ```bash
  pip install pymisp
  ```
- Target detection tooling reachable: Suricata, Sigma toolchain (`pip install sigma-cli`), and/or Wazuh manager.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1589 | Gather Victim Identity Information | Feeds capture adversary reconnaissance indicators; operationalizing them detects/contextualizes such activity. |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 domain/URL IOCs from feeds become Suricata/Sigma detections for malicious HTTP(S). |
| T1071.004 | Application Layer Protocol: DNS | Malicious-domain IOCs feed DNS-based detection (Wazuh/Suricata). |
| T1105 | Ingress Tool Transfer | File-hash IOCs from feeds detect known malicious payload delivery. |

## Workflow

### 1. Add and enable feed
Register reputable source and turn it on.
```python
# add_feed.py (PyMISP) — register the CIRCL OSINT feed
from pymisp import PyMISP, MISPFeed
misp = PyMISP("https://localhost", "YOUR_AUTH_KEY", ssl=False)
feed = MISPFeed()
feed.name = "CIRCL OSINT Feed"
feed.provider = "CIRCL"
feed.url = "https://www.circl.lu/doc/misp/feed-osint"
feed.source_format = "misp"
feed.input_source = "network"
feed.enabled = True
print(misp.add_feed(feed, pythonify=True))
```

### 2. Cache enabled feeds for real-time correlation
Caching loads feed IOCs into Redis so lookups are instant.
```python
# Cache all enabled feeds (equivalent to "Enable caching" in the UI)
print(misp.cache_all_feeds())
# Or fetch a single feed's events into the instance by feed id:
print(misp.fetch_feed(1))
```

### 3. Enable warninglists to reduce false positives
Turn on known-good lists so non-actionable indicators are flagged.
```python
# Enable the common false-positive warninglists
for wl in misp.warninglists(pythonify=True):
    if wl.name in ("List of RFC 1918 CIDR blocks",
                   "Top 1000 website from Cisco Umbrella",
                   "List of known public DNS resolvers"):
        misp.toggle_warninglist(warninglist_id=wl.id, force_enable=True)
```

### 4. Authenticate and search for fresh IOCs
Pull recently published, TLP-scoped, to-IDS attributes only.
```python
from pymisp import PyMISP
misp = PyMISP("https://localhost", "YOUR_AUTH_KEY", ssl=False)
# Only export attributes flagged to_ids=1, published, last 7 days, IP/domain/url/hash
attrs = misp.search(
    controller="attributes",
    type_attribute=["ip-dst", "domain", "url", "md5", "sha256"],
    to_ids=True, published=True, last="7d",
    enforce_warninglist=True,   # drop warninglisted (known-good) values
    pythonify=True,
)
print(f"{len(attrs)} actionable IOCs")
```

### 5. Export Suricata/Snort rules via REST API
MISP renders matching attributes directly as IDS rules.
```bash
# Suricata rules for all to_ids network IOCs (NIDS export)
curl -s -k -H "Authorization: YOUR_AUTH_KEY" -H "Accept: application/json" \
  "https://localhost/attributes/restSearch/returnFormat:suricata/to_ids:1/type:domain%7Cip-dst%7Curl" \
  -o misp_suricata.rules
# Snort equivalent
curl -s -k -H "Authorization: YOUR_AUTH_KEY" -H "Accept: application/json" \
  "https://localhost/attributes/restSearch/returnFormat:snort/to_ids:1" -o misp_snort.rules
```

### 6. Deploy Suricata rules
Load and reload.
```bash
cp misp_suricata.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml   # validate config + rules
suricatasc -c reload-rules                    # hot reload
```

### 7. Generate Wazuh CDB lists from IOCs
Convert MISP domains/IPs into Wazuh CDB lookup list referenced by rule.
```python
# Build a Wazuh CDB list (key:value per line) from the searched attributes
with open("misp_iocs.cdb", "w") as fh:
    for a in attrs:
        if a.type in ("domain", "ip-dst"):
            fh.write(f"{a.value}:\n")
# On the Wazuh manager: place under /var/ossec/etc/lists/, reference in ossec.conf:
#   <list>etc/lists/misp_iocs</list>
# then compile and restart:
#   /var/ossec/bin/wazuh-control restart
```

### 8. Generate Sigma rules from MISP intelligence
Emit Sigma rule matching exported domains.
```python
import yaml
domains = [a.value for a in attrs if a.type == "domain"]
sigma = {
    "title": "MISP feed malicious domain contact",
    "status": "experimental",
    "logsource": {"category": "dns"},
    "detection": {"selection": {"query|contains": domains}, "condition": "selection"},
    "level": "high",
    "tags": ["attack.command_and_control", "attack.t1071.004"],
}
with open("misp_domains.yml", "w") as fh:
    yaml.safe_dump(sigma, fh, sort_keys=False)
```

### 9. Convert and deploy Sigma to your SIEM backend
Use `sigma-cli` to compile to target backend (Splunk, Elastic, etc.).
```bash
sigma convert -t splunk -p splunk_windows misp_domains.yml > misp_domains.spl
sigma convert -t elasticsearch misp_domains.yml > misp_domains.eql
```

### 10. Schedule pipeline and run bundled helper
`agent.py` searches MISP and writes Suricata/Sigma/Wazuh artifacts in one pass; schedule it via cron.
```bash
python scripts/agent.py --url https://localhost --key YOUR_AUTH_KEY \
  --last 7d --outdir ./detections --insecure
# crontab: 0 * * * * /usr/bin/python /path/scripts/agent.py ... >> /var/log/misp_pipeline.log 2>&1
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| MISP | Threat-intelligence platform | https://www.misp-project.org/ |
| misp-docker | Maintained container deployment | https://github.com/MISP/misp-docker |
| PyMISP | Python client for MISP REST API | https://github.com/MISP/PyMISP |
| MISP warninglists | Known-good lists for FP reduction | https://github.com/MISP/misp-warninglists |
| MISP automation docs | REST API + export formats | https://www.circl.lu/doc/misp/automation/ |
| sigma-cli | Sigma rule conversion | https://github.com/SigmaHQ/sigma-cli |
| Wazuh CDB lists | IOC lookup lists for Wazuh | https://documentation.wazuh.com/ |

## Validation Criteria

- [ ] MISP instance reachable and Auth Key created.
- [ ] At least one reputable feed enabled and cached.
- [ ] Relevant warninglists enabled and `enforce_warninglist` applied to searches.
- [ ] PyMISP search returns scoped, to_ids, non-warninglisted IOCs.
- [ ] Suricata/Snort rules exported via REST and validated with `suricata -T`.
- [ ] Wazuh CDB list generated and loaded by manager.
- [ ] Sigma rule generated and converted to SIEM backend.
- [ ] Generated detections confirmed to load (and fire on test IOC).
- [ ] Pipeline scheduled and logging successfully.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/operationalizing-misp-threat-feeds
