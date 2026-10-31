---
name: implementing-runtime-application-self-protection
description: Deploy Runtime Application Self-Protection (RASP) agents to detect and block attacks from within application runtime, covering OpenRASP integration, attack pattern detection, and security policy configuration for Java and Python web applications.
subdomain: application-security
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1059.007
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
upstream: implementing-runtime-application-self-protection@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Java 8+ application server (Tomcat, Spring Boot, or JBoss) or Python Flask/Django application
- OpenRASP agent package (rasp-java or equivalent)
- OpenRASP management console for centralized policy management
- SIEM integration endpoint (Splunk HEC, Elasticsearch, or syslog)
- Application staging environment for RASP testing before production

## Steps

### Step 1: Deploy RASP Agent

Install RASP agent into application server runtime using JVM agent attachment for Java or middleware hooks for Python.

### Step 2: Configure Detection Policies

Define detection rules for SQL injection, command injection, SSRF, path traversal, XXE, and deserialization attacks with block or monitor actions.

### Step 3: Tune and Baseline

Run agent in monitor mode during normal operations to establish baseline behavior and tune policies to reduce false positives before switching to block mode.

### Step 4: Integrate with SIEM

Forward RASP alerts to SIEM for correlation with WAF, IDS, and authentication events to build comprehensive attack timelines.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-runtime-application-self-protection
