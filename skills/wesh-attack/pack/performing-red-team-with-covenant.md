---
name: performing-red-team-with-covenant
description: Conducts red team operations using the Covenant C2 framework for authorized adversary simulation, covering listener setup, grunt deployment, task execution, and lateral movement tracking.
subdomain: red-team
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1021
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: performing-red-team-with-covenant@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Covenant C2 server deployed (Docker or .NET 6)
- Python 3.9+ with `requests` library
- Covenant API token (obtained via /api/users/login)
- Written authorization for red team engagement
- Isolated lab or authorized target environment

## Steps

### Step 1: Authenticate to Covenant API

Obtain JWT token by posting credentials to /api/users/login endpoint.

### Step 2: Create Listener

Configure HTTP or HTTPS listener with callback URLs and bind address.

### Step 3: Generate Launcher

Create binary, PowerShell, or MSBuild launcher tied to listener for grunt deployment.

### Step 4: Deploy and Manage Grunts

Monitor grunt callbacks, execute tasks, and collect output from compromised hosts.

### Step 5: Document Operations

Generate operations report documenting all actions, timestamps, and findings.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-red-team-with-covenant
