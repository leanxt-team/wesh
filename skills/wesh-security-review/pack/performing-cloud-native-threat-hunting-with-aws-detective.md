---
name: performing-cloud-native-threat-hunting-with-aws-detective
description: Investigate AWS security incidents using Amazon Detective's behavior graphs, built from CloudTrail, VPC Flow Logs, GuardDuty, and EKS audit logs, to trace entity timelines and profile IAM users, roles, EC2 instances, and IP addresses for lateral movement.
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
upstream: performing-cloud-native-threat-hunting-with-aws-detective@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- AWS account with Detective enabled (requires GuardDuty active for 48+ hours)
- AWS CLI v2 configured with appropriate IAM permissions (`detective:*`, `guardduty:List*`)
- Python 3.9+ with boto3
- IAM policy: `AmazonDetectiveFullAccess` or custom policy with `detective:SearchGraph`, `detective:GetInvestigation`, `detective:ListIndicators`

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Behavior Graph** | Data structure linking CloudTrail, VPC Flow, GuardDuty, and EKS logs for account/region |
| **Entity** | Investigable object: IAM user, IAM role, EC2 instance, IP address, S3 bucket, EKS cluster |
| **Finding Group** | Correlated set of GuardDuty findings linked to same attack campaign |
| **Entity Profile** | Timeline of API calls, network connections, and resource access for specific entity |
| **Scope Time** | Investigation window (default 24h, max 1 year) for behavioral analysis |

## Steps

### Step 1: List Available Behavior Graphs

```bash
aws detective list-graphs --output table
```

### Step 2: Investigate Suspicious IAM User

```bash
# Get entity profile for an IAM user
aws detective get-investigation \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001
```

### Step 3: Search Entities Programmatically

```python
#!/usr/bin/env python3
"""Search AWS Detective for suspicious entities."""
import boto3
import json
from datetime import datetime, timedelta
detective = boto3.client('detective')
def list_behavior_graphs():
    """List all Detective behavior graphs."""
    response = detective.list_graphs()
    return response.get('GraphList', [])
def get_investigation_indicators(graph_arn, investigation_id, max_results=50):
    """Get indicators for a specific investigation."""
    response = detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
        MaxResults=max_results
    )
    return response.get('Indicators', [])
def investigate_guardduty_findings(graph_arn):
    """List high-severity investigations correlated by Detective."""
    response = detective.list_investigations(
        GraphArn=graph_arn,
        FilterCriteria={
            'Severity': {'Value': 'CRITICAL'},
            'Status': {'Value': 'RUNNING'}
        },
        MaxResults=20
    )
    for investigation in response.get('InvestigationDetails', []):
        print(f"Investigation: {investigation['InvestigationId']}")
        print(f"  Entity: {investigation['EntityArn']}")
        print(f"  Status: {investigation['Status']}")
        print(f"  Severity: {investigation['Severity']}")
        print(f"  Created: {investigation['CreatedTime']}")
        print()
if __name__ == "__main__":
    graphs = list_behavior_graphs()
    for graph in graphs:
        print(f"Graph: {graph['Arn']}")
        investigate_guardduty_findings(graph['Arn'])
```

### Step 4: Analyze Finding Groups for Attack Campaigns

```bash
# List investigations with high severity
aws detective list-investigations \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --filter-criteria '{"Severity":{"Value":"HIGH"}}' \
  --max-results 10
```

### Step 5: Check Entity Indicators

```bash
# Get indicators for a specific investigation
aws detective list-indicators \
  --graph-arn arn:aws:detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001 \
  --max-results 50
```

## Verification

1. Confirm behavior graph has data: `aws detective list-graphs` returns non-empty list
2. Validate investigation results contain entity timelines with API call sequences
3. Cross-reference Detective findings with raw CloudTrail logs for accuracy
4. Verify finding group correlations match manual investigation conclusions
5. Confirm automated alerts trigger for HIGH/CRITICAL severity investigations

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-cloud-native-threat-hunting-with-aws-detective
