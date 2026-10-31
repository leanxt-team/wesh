---
name: implementing-log-forwarding-with-fluentd
description: Configures Fluent Bit as an endpoint log forwarder and Fluentd as the central aggregator for centralized log collection, routing, filtering, and enrichment, covering input plugins for syslog/file-tailing/application logs and output routing to Elasticsearch, S3, and Splunk.
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
upstream: implementing-log-forwarding-with-fluentd@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Fluentd (td-agent) v1.16+ or Fluent Bit v3.0+
- Python 3.8+ with fluent-logger library
- Elasticsearch or Splunk for log destination
- Network access on port 24224 (Fluentd forward protocol)
- Ruby 2.7+ (for Fluentd plugin development)

## Steps

1. **Generate Fluent Bit Configuration** — Create input, filter, and output configuration for endpoint log collection
2. **Generate Fluentd Aggregator Configuration** — Configure central Fluentd instance with forward input, parsing, and multi-output routing
3. **Configure Log Filtering and Enrichment** — Add record_transformer and grep filters for log enrichment and noise reduction
4. **Validate Configuration Syntax** — Parse and validate Fluentd/Fluent Bit configuration files for syntax errors
5. **Test Log Forwarding** — Send test events via fluent-logger Python library and verify delivery
6. **Generate Deployment Report** — Produce configuration summary with routing topology and health metrics

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-log-forwarding-with-fluentd
