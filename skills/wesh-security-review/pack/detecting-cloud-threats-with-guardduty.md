---
name: detecting-cloud-threats-with-guardduty
description: Deploy and operationalize Amazon GuardDuty, covering protection plans for S3, EKS, EC2 runtime monitoring, and Lambda, interpreting finding severity, and building automated response with EventBridge and Lambda.
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
upstream: detecting-cloud-threats-with-guardduty@54a7988 Apache-2.0, modified by wesh
---
Not for: Azure or GCP threat detection (see securing-azure-with-microsoft-defender or auditing-gcp-security-posture), for static code analysis, or for compliance posture monitoring (see implementing-aws-security-hub).

## Prerequisites

- AWS account with GuardDuty administrative permissions (guardduty:*)
- AWS CloudTrail, VPC Flow Logs, and DNS query logs enabled (GuardDuty consumes these automatically)
- AWS Organizations configured if deploying GuardDuty across multi-account estate
- EventBridge and Lambda configured for automated response workflows

## Workflow

### Step 1: Enable GuardDuty and Protection Plans

Activate GuardDuty at organization level using delegated administrator account. Enable all protection plans including S3 Protection, EKS Audit Log Monitoring, Runtime Monitoring, Malware Protection, RDS Login Activity, and Lambda Network Activity Monitoring.

```bash
# Enable GuardDuty as organization delegated administrator
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}}
  }'
# Enable Runtime Monitoring for EC2 and ECS
aws guardduty update-detector \
  --detector-id <detector-id> \
  --features '[
    {"Name": "RUNTIME_MONITORING", "Status": "ENABLED",
     "AdditionalConfiguration": [
       {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
       {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"}
     ]}
  ]'
# Designate delegated admin for multi-account
aws guardduty enable-organization-admin-account \
  --admin-account-id 111122223333
```

### Step 2: Configure Multi-Account Aggregation

Automatically enroll all organization member accounts and configure finding export to centralized S3 bucket for retention and SIEM ingestion.

```bash
# Auto-enable GuardDuty for all org members
aws guardduty update-organization-configuration \
  --detector-id <detector-id> \
  --auto-enable-organization-members ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]'
# Configure finding export to S3
aws guardduty create-publishing-destination \
  --detector-id <detector-id> \
  --destination-type S3 \
  --destination-properties '{
    "DestinationArn": "arn:aws:s3:::guardduty-findings-centralized",
    "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-id"
  }'
```

### Step 3: Interpret Finding Types and Severity Levels

GuardDuty classifies findings into four severity levels: Critical, High, Medium, and Low. Each finding type follows format ThreatPurpose:ResourceType/ThreatName. Extended Threat Detection generates attack sequence findings that correlate multiple events across time.

Key finding categories:
- **Recon**: Port scanning, API enumeration (e.g., Recon:EC2/PortProbeUnprotectedPort)
- **UnauthorizedAccess**: Credential abuse, console logins from unusual locations
- **CryptoCurrency**: Mining activity detected on instances (e.g., CryptoCurrency:EC2/BitcoinTool.B)
- **Impact**: Resource hijacking, data destruction attempts
- **AttackSequence**: Multi-stage attacks correlating initial access through lateral movement to impact (Critical severity)

### Step 4: Build Automated Response with EventBridge

Create EventBridge rules that route GuardDuty findings to Lambda functions for automated containment actions e.g. isolating compromised EC2 instances, revoking IAM credentials, or blocking malicious IP addresses.

```bash
# EventBridge rule for high/critical GuardDuty findings
aws events put-rule \
  --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7]}]
    }
  }'
# Target Lambda function for auto-remediation
aws events put-targets \
  --rule GuardDutyHighSeverity \
  --targets '[{
    "Id": "AutoRemediateTarget",
    "Arn": "arn:aws:lambda:us-east-1:123456789012:function/guardduty-auto-remediate"
  }]'
```

Auto-remediation Lambda example for isolating compromised EC2 instance:

```python
import boto3
def lambda_handler(event, context):
    finding = event['detail']
    finding_type = finding['type']
    severity = finding['severity']
    if finding_type.startswith('UnauthorizedAccess:EC2') and severity >= 7:
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')
        # Create isolation security group (no inbound/outbound rules)
        vpc_id = finding['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        isolation_sg = ec2.create_security_group(
            GroupName=f'isolation-{instance_id}',
            Description='GuardDuty auto-isolation',
            VpcId=vpc_id
        )
        # Replace all security groups with isolation group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg['GroupId']]
        )
        # Tag instance for investigation
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'SecurityStatus', 'Value': 'ISOLATED'},
                  {'Key': 'GuardDutyFinding', 'Value': finding_type}]
        )
        return {'status': 'isolated', 'instance': instance_id}
```

### Step 5: Investigate Extended Threat Detection Attack Sequences

Review Critical-severity attack sequence findings that correlate multiple signals across EC2, ECS, and EKS. These findings represent multi-stage attacks e.g. initial access through compromised credentials followed by persistence, lateral movement, and crypto mining.

```bash
# List critical attack sequence findings
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 9},
      "type": {"Eq": ["AttackSequence:EC2/CompromisedInstanceGroup",
                       "AttackSequence:ECS/CompromisedCluster",
                       "AttackSequence:EKS/CompromisedCluster"]}
    }
  }'
# Get full finding details with attack sequence timeline
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id>
```

### Step 6: Integrate with Security Hub and SIEM

Forward GuardDuty findings to AWS Security Hub for centralized aggregation and to external SIEM platforms via S3 export or Amazon Security Lake for long-term retention and cross-source correlation.

```bash
# Verify GuardDuty integration with Security Hub
aws securityhub get-enabled-standards
# Enable Amazon Security Lake with GuardDuty as a source
aws securitylake create-data-lake \
  --configurations '[{
    "region": "us-east-1",
    "lifecycleConfiguration": {
      "expiration": {"days": 365}
    }
  }]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Extended Threat Detection | GuardDuty capability that correlates multiple signals across time to detect multi-stage attacks, generating Critical-severity attack sequence findings |
| Runtime Monitoring | Protection plan that deploys security agent to EC2 instances, ECS tasks, and EKS pods to detect runtime threats at OS level |
| Finding Severity | Four-tier classification (Low, Medium, High, Critical) where Critical indicates confirmed multi-stage attacks requiring immediate response |
| Malware Protection | On-demand and automatic EBS volume scanning triggered by suspicious EC2 behavior to detect malware without agent installation |
| Delegated Administrator | Organization member account designated to manage GuardDuty across all accounts in AWS Organization |
| Suppression Rule | Filter that automatically archives findings matching specific criteria to reduce noise from known benign activity |
| Threat Intelligence | IP reputation lists and domain threat feeds used by GuardDuty to identify communication with known malicious infrastructure |

## Tools & Systems

- **Amazon GuardDuty**: Core threat detection service analyzing CloudTrail, VPC Flow Logs, DNS logs, and runtime telemetry
- **Amazon EventBridge**: Serverless event bus for routing GuardDuty findings to automated response targets
- **AWS Security Hub**: Centralized security findings aggregation supporting automated remediation workflows
- **Amazon Security Lake**: OCSF-normalized data lake for long-term security log retention and cross-service correlation
- **Amazon Detective**: Graph-based investigation service that visualizes relationships between GuardDuty findings, resources, and API activity

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-cloud-threats-with-guardduty
