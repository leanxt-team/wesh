---
name: implementing-zero-trust-with-beyondcorp
description: Configures Google BeyondCorp Enterprise Identity-Aware Proxy (IAP) as the access enforcement point for web applications, defining Access Context Manager access levels from device trust and network attributes, and auditing the resulting policies for compliance.
subdomain: zero-trust
facing: config
mitre_attack:
- T1078
- T1550
- T1021
- T1556
- T1078.004
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
upstream: implementing-zero-trust-with-beyondcorp@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Google Cloud project with BeyondCorp Enterprise license
- IAP API enabled (iap.googleapis.com)
- Access Context Manager API enabled (accesscontextmanager.googleapis.com)
- GCP resources to protect (Compute Engine, App Engine, or GKE services)
- Endpoint Verification deployed on managed devices
- Python 3.9+ with google-cloud-iap library

## Steps

### Step 1: Enable IAP on Target Resources
Configure Identity-Aware Proxy on Compute Engine, App Engine, or HTTPS load balancer backends.

### Step 2: Define Access Levels
Create Access Context Manager access levels based on IP ranges, device attributes (OS version, encryption, screen lock), and geographic location.

### Step 3: Bind Access Policies
Apply access levels as IAP conditions to enforce context-aware access decisions on protected resources.

### Step 4: Audit and Monitor
Query IAP audit logs, verify policy enforcement, and identify gaps in zero trust coverage.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-zero-trust-with-beyondcorp
