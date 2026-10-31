---
name: modeling-threats-with-opencti
description: Deploy OpenCTI (Filigran) via Docker Compose and use the pycti Python client to model threat actors, intrusion sets, campaigns, and indicators as a STIX 2.1 knowledge graph with relationships (uses, attributed-to, targets).
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1589
nist_csf:
- ID.RA-03
upstream: modeling-threats-with-opencti@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Docker and Docker Compose (OpenCTI is deployed as container stack)
- Python 3.8+ for pycti client:
  ```bash
  pip install pycti stix2
  ```
- OpenCTI instance and API token (Profile > API access in UI)
- Familiarity with STIX 2.1 data model (SDOs, SROs, observables)
- RabbitMQ, Redis, and Elasticsearch/OpenSearch reachable by platform (handled by reference compose)

## MITRE ATT&CK Mapping

| ID | Name | Relevance |
|----|------|-----------|
| T1589 | Gather Victim Identity Information | OpenCTI consolidates reconnaissance and victim/target intelligence observed across reporting into structured, queryable knowledge graph that supports analysis of adversary targeting. |

## Workflow

### Step 1: Deploy OpenCTI platform
Use official Docker Compose stack. Generate required tokens/UUIDs and start platform, workers, and dependencies.
```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker
# Generate required secrets (UUID v4 for tokens, base64 for app secret)
cat > .env <<EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.local
OPENCTI_ADMIN_PASSWORD=$(openssl rand -hex 16)
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_BASE_URL=http://localhost:8080
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
EOF
# Increase vm.max_map_count for Elasticsearch, then start the stack
sudo sysctl -w vm.max_map_count=1048575
docker compose up -d
```
Access UI at http://localhost:8080 and log in with admin credentials from `.env`.

### Step 2: Authenticate with pycti
Create an `OpenCTIApiClient` instance using your platform URL and API token.
```python
from pycti import OpenCTIApiClient
opencti = OpenCTIApiClient(
    "http://localhost:8080",
    "YOUR_API_TOKEN",  # from Profile > API access, or OPENCTI_ADMIN_TOKEN
)
```

### Step 3: Create core STIX domain objects
Create Threat Actor, Intrusion Set, Campaign, and Attack Pattern. pycti `create()` calls act as upserts when `update=True`.
```python
# Threat Actor (group)
actor = opencti.threat_actor_group.create(
    name="APT-EXAMPLE",
    description="Financially motivated intrusion group tracked in this case.",
    threat_actor_types=["crime-syndicate"],
)
# Intrusion Set
intrusion_set = opencti.intrusion_set.create(
    name="EXAMPLE-SET",
    description="Cluster of activity sharing infrastructure and TTPs.",
)
# Campaign
campaign = opencti.campaign.create(
    name="Operation Example 2026",
    description="Spearphishing campaign targeting the finance sector.",
)
# Attack Pattern linked to MITRE ATT&CK (x_mitre_id maps to the technique)
technique = opencti.attack_pattern.create(
    name="Spearphishing Attachment",
    x_mitre_id="T1566.001",
)
```

### Step 4: Build relationships to form graph
Connect objects with STIX relationships so graph reflects how adversary operates.
```python
# Intrusion set attributed to the threat actor
opencti.stix_core_relationship.create(
    fromId=intrusion_set["id"],
    toId=actor["id"],
    relationship_type="attributed-to",
)
# Campaign attributed to the intrusion set
opencti.stix_core_relationship.create(
    fromId=campaign["id"],
    toId=intrusion_set["id"],
    relationship_type="attributed-to",
)
# Intrusion set uses the technique
opencti.stix_core_relationship.create(
    fromId=intrusion_set["id"],
    toId=technique["id"],
    relationship_type="uses",
)
```

### Step 5: Add indicators and observables
Create indicator with STIX pattern and tie it to intrusion set via an `indicates` relationship.
```python
from dateutil.parser import parse
date = parse("2026-06-01").strftime("%Y-%m-%dT%H:%M:%SZ")
indicator = opencti.indicator.create(
    name="C2 domain for Operation Example",
    pattern_type="stix",
    pattern="[domain-name:value = 'malicious-c2.example']",
    x_opencti_main_observable_type="Domain-Name",
    valid_from=date,
)
opencti.stix_core_relationship.create(
    fromId=indicator["id"],
    toId=intrusion_set["id"],
    relationship_type="indicates",
)
```

### Step 6: Submit STIX 2.1 bundle directly
For bulk ingestion, build STIX bundle and submit it with `send_stix2_bundle` — recommended bulk-ingest path.
```python
import json
with open("threat_report_bundle.json") as f:
    bundle = json.load(f)
opencti.stix2.import_bundle_from_json(
    json.dumps(bundle),
    update=True,
)
```

### Step 7: Enable connectors for automated ingestion
Add connectors to compose stack so external intelligence (MITRE ATT&CK, MISP) is ingested continuously. Each connector needs its own token.
```yaml
# Append to docker-compose.yml under services:
  connector-mitre:
    image: opencti/connector-mitre:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${CONNECTOR_MITRE_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_MITRE_ID}
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MITRE ATT&CK
      - CONNECTOR_SCOPE=tool,report,malware,identity,attack-pattern,intrusion-set,campaign
      - MITRE_INTERVAL=7   # days
    restart: always
```
```bash
docker compose up -d connector-mitre
```

### Step 8: Query graph and export actor profile
Read back adversary's full picture for reporting and detection engineering.
```python
# Resolve all techniques an intrusion set uses
iset = opencti.intrusion_set.read(filters={
    "mode": "and",
    "filters": [{"key": "name", "values": ["EXAMPLE-SET"]}],
    "filterGroups": [],
})
rels = opencti.stix_core_relationship.list(
    fromId=iset["id"],
    relationship_type="uses",
)
for r in rels:
    print(r["to"]["name"], r["to"].get("x_mitre_id"))
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| OpenCTI Platform | STIX 2.1 threat-intel knowledge graph | https://github.com/OpenCTI-Platform/opencti |
| OpenCTI Docker | Reference compose stack | https://github.com/OpenCTI-Platform/docker |
| pycti | Official Python client for GraphQL API | https://github.com/OpenCTI-Platform/client-python |
| OpenCTI Connectors | Importers (MITRE, MISP, OTX, CISA, abuse.ch) | https://github.com/OpenCTI-Platform/connectors |
| OpenCTI docs | Official documentation | https://docs.opencti.io/latest/ |
| STIX 2.1 spec | Underlying data model | https://oasis-open.github.io/cti-documentation/ |

## STIX Object Cheat Sheet (pycti entities)

| pycti entity | STIX type | Use |
|--------------|-----------|-----|
| `threat_actor_group` | threat-actor | Named adversary group |
| `intrusion_set` | intrusion-set | Clustered activity / tracked set |
| `campaign` | campaign | Time-bounded operation |
| `attack_pattern` | attack-pattern | MITRE ATT&CK technique |
| `malware` | malware | Tooling/implant |
| `indicator` | indicator | Detection pattern (STIX/Sigma/YARA) |
| `vulnerability` | vulnerability | CVE |
| `stix_core_relationship` | relationship | `uses`, `attributed-to`, `targets`, `indicates` |

## Validation Criteria

- [ ] OpenCTI platform and workers deployed and reachable at base URL
- [ ] pycti authenticates with valid API token
- [ ] Threat Actor, Intrusion Set, Campaign, and Attack Pattern objects created
- [ ] Relationships (`attributed-to`, `uses`, `indicates`) built between objects
- [ ] At least one indicator created and linked to intrusion set
- [ ] A STIX 2.1 bundle ingested via `import_bundle_from_json`
- [ ] MITRE ATT&CK connector enabled and importing techniques
- [ ] Intrusion-set TTP profile queryable and exportable

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/modeling-threats-with-opencti
