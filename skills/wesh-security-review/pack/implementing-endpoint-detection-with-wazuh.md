---
name: implementing-endpoint-detection-with-wazuh
description: Deploys and configures Wazuh SIEM/XDR for endpoint detection, covering agent authentication and management, custom decoder and rule XML creation, alert querying via the Wazuh REST API, rule testing with wazuh-logtest, and automated active-response actions.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1685.002
- T1685.005
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-endpoint-detection-with-wazuh@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Wazuh Manager 4.x deployed with API enabled
- Python 3.9+ with `requests` library
- API credentials (username/password for JWT authentication)
- Understanding of Wazuh decoder and rule XML syntax

## Steps

### Step 1: Authenticate to Wazuh API
Obtain JWT token via POST to /security/user/authenticate.

### Step 2: List and Monitor Agents
Query agent status, versions, and last keep-alive via /agents endpoint.

### Step 3: Query Security Alerts
Search alerts by rule ID, severity, agent, or time range.

### Step 4: Test Custom Rules with Logtest
Use the /logtest endpoint to validate decoder and rule logic against sample log lines.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-endpoint-detection-with-wazuh
