---
name: implementing-security-chaos-engineering
description: Implements security chaos engineering experiments that deliberately disable or degrade security controls to verify detection and response capabilities.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1027
- T1070
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-security-chaos-engineering@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with security operations concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Design and execute security chaos experiments that intentionally break security
controls to verify that detection, alerting, and response systems work correctly.

```python
# Example: Verify detection when a security group is opened
import boto3
ec2 = boto3.client("ec2")
# Chaos experiment: temporarily add 0.0.0.0/0 rule
ec2.authorize_security_group_ingress(
    GroupId="sg-12345",
    IpProtocol="tcp", FromPort=22, ToPort=22,
    CidrIp="0.0.0.0/0",
)
# Verify: does GuardDuty/Config alert fire within SLA?
# Rollback: remove the rule after verification
```

Key experiments:
1. Open security group and verify Config Rule alerts
2. Disable CloudTrail and verify detection time
3. Create IAM admin user and verify alert triggers
4. Simulate log pipeline failure and check monitoring gaps
5. Deploy test malware hash and verify EDR response

## Examples

```python
# Rollback function for safe experiment execution
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()
        result = verify_fn(timeout)
    finally:
        rollback_fn()
    return result
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-security-chaos-engineering
