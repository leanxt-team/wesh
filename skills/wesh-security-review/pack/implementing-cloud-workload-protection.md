---
name: implementing-cloud-workload-protection
description: Implements cloud workload protection using boto3 and google-cloud APIs for runtime security monitoring, process anomaly detection, and file integrity checking on EC2/GCE instances.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1071
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: implementing-cloud-workload-protection@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with cloud security concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Monitor cloud workloads for runtime threats by checking process lists, network
connections, file integrity, and resource utilization anomalies.

```python
import boto3
ssm = boto3.client("ssm")
# Run command on EC2 instances to check for suspicious processes
response = ssm.send_command(
    InstanceIds=["i-1234567890abcdef0"],
    DocumentName="AWS-RunShellScript",
    Parameters={"commands": ["ps aux | grep -E 'xmrig|minerd|cryptonight'"]},
)
```

Key protection areas:
1. Process monitoring for cryptominers and reverse shells
2. File integrity monitoring on critical system files
3. Network connection auditing for C2 callbacks
4. Resource utilization anomaly detection (CPU spikes)
5. Unauthorized binary detection via hash comparison

## Examples

```python
# Check for unauthorized outbound connections
ssm.send_command(
    InstanceIds=instances,
    DocumentName="AWS-RunShellScript",
    Parameters={"commands": ["ss -tlnp | grep ESTABLISHED"]},
)
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-cloud-workload-protection
