---
name: detecting-insider-threat-with-ueba
description: Implement User and Entity Behavior Analytics (UEBA) using Elasticsearch/OpenSearch to build behavioral baselines, calculate anomaly scores, perform peer group analysis, and alert on insider threat indicators such as data exfiltration, privilege abuse, and unauthorized access.
subdomain: threat-detection
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1048
- T1041
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
upstream: detecting-insider-threat-with-ueba@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Elasticsearch 8.x or OpenSearch 2.x cluster with security audit data
- Log sources: Active Directory authentication, VPN, DLP, file server access, email
- Python 3.9+ with elasticsearch client library
- Baseline period of 30+ days of normal user activity data
- Defined peer groups based on department, role, or job function

## Steps

### Step 1: Ingest and Normalize Activity Logs
Configure log pipelines to ingest authentication, file access, email, and network logs into Elasticsearch with unified user identity field.

### Step 2: Build Behavioral Baselines
Calculate per-user baselines for login times, data volume, application usage, and access patterns over rolling 30-day window using Elasticsearch aggregations.

### Step 3: Calculate Anomaly Scores
Compare current activity against baselines using z-score deviation and peer group comparison to generate per-user risk scores.

### Step 4: Correlate and Alert
Combine multiple anomalous indicators (unusual hours + large downloads + new system access) into composite risk scores that trigger SOC investigation workflows.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-insider-threat-with-ueba
