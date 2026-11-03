---
name: emulating-cloud-attacks-with-stratus-red-team
description: Install and run Stratus Red Team to detonate granular, MITRE ATT&CK-mapped AWS, Azure, GCP, and Kubernetes attack techniques through their warmup-detonate-revert-cleanup lifecycle, then verify the telemetry they generate.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078
nist_csf:
- DE.CM-01
upstream: emulating-cloud-attacks-with-stratus-red-team@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and detection-validation purposes only. Stratus Red Team spins up and modifies real cloud infrastructure in the account whose credentials you supply. Only run it in accounts you own or are explicitly authorized to test. Always `cleanup` afterwards to avoid orphaned, billable, or insecure resources. Unauthorized use against systems you do not control is illegal.

## Prerequisites

- Stratus Red Team binary (Go 1.23+ to build from source, or Homebrew/Docker):
  ```bash
  # Go install
  go install -v github.com/datadog/stratus-red-team/v2/cmd/stratus@latest

  # Homebrew
  brew tap datadog/stratus-red-team https://github.com/DataDog/stratus-red-team
  brew install datadog/stratus-red-team/stratus-red-team

  # Docker
  docker run --rm -v $HOME/.stratus-red-team/:/root/.stratus-red-team/ \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
    ghcr.io/datadog/stratus-red-team list
  ```
- Authenticated cloud credentials for target provider:
  ```bash
  # AWS — verify identity before detonating
  export AWS_PROFILE=stratus-lab
  aws sts get-caller-identity

  # Azure
  az login

  # GCP
  gcloud auth application-default login

  # Kubernetes
  kubectl config current-context
  ```
- Dedicated, non-production lab account or subscription (techniques create real resources)
- Terraform is embedded; no separate install is required, but outbound HTTPS to download provider plugins on first warmup is needed

## MITRE ATT&CK Mapping

| ID | Name | Use in this skill |
|----|------|-------------------|
| T1078 | Valid Accounts | Emulation runs as valid cloud identity; many techniques abuse legitimate credentials/API access |
| T1078.004 | Valid Accounts: Cloud Accounts | e.g. `aws.credential-access.ec2-steal-instance-credentials` produces cloud-account abuse telemetry |
| T1580 | Cloud Infrastructure Discovery | Discovery-tactic techniques such as `aws.discovery.*` |
| T1530 | Data from Cloud Storage | Exfiltration techniques such as `aws.exfiltration.ec2-share-ebs-snapshot` |
| T1098 | Account Manipulation | Persistence techniques such as `aws.persistence.iam-create-admin-user` |

## Workflow

### 1. Confirm identity and list technique catalog

Always confirm which account you are about to attack, then browse catalog.
```bash
aws sts get-caller-identity
stratus list
# Filter to a single platform
stratus list --platform aws
# Filter by MITRE ATT&CK tactic
stratus list --mitre-attack-tactic credential-access
```

### 2. Inspect specific technique before running it

Read exactly what technique will do and which detonation/telemetry it produces.
```bash
stratus show aws.credential-access.ec2-steal-instance-credentials
```

### 3. Warm up prerequisite infrastructure

Provision prerequisites with embedded Terraform without performing attack yet.
```bash
stratus warmup aws.credential-access.ec2-steal-instance-credentials
stratus status
```

### 4. Detonate technique

Execute malicious actions; this is what your detections must catch. Warmup is implicit if not already done.
```bash
stratus detonate aws.credential-access.ec2-steal-instance-credentials
# Detonate and force a re-warmup in one step
stratus detonate aws.persistence.iam-create-admin-user --force
```

### 5. Inspect status and telemetry generated

Check lifecycle state, then pull corresponding control-plane logs to confirm attack landed.
```bash
stratus status
# Pull recent CloudTrail events to verify the detonation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 10
```

### 6. Validate detection

Confirm your SIEM/detection fired. Example: query Athena/CloudTrail or check GuardDuty findings.
```bash
aws guardduty list-findings --detector-id "$DETECTOR_ID" \
  --finding-criteria '{"Criterion":{"updatedAt":{"GreaterThanOrEqual":'"$(date -d '-1 hour' +%s)"'000}}}'
```

### 7. Revert side effects to re-detonate

Undo detonation while keeping prerequisites so you can iterate on detection.
```bash
stratus revert aws.credential-access.ec2-steal-instance-credentials
stratus detonate aws.credential-access.ec2-steal-instance-credentials   # run again
```

### 8. Clean up all infrastructure

Tear down everything technique created. Always finish here.
```bash
stratus cleanup aws.credential-access.ec2-steal-instance-credentials
# Nuke everything Stratus ever provisioned in this account
stratus cleanup --all
stratus status   # confirm COLD state for all techniques
```

### 9. Drive it programmatically for coverage runs

Loop over tactic to measure detection coverage, then clean up. See `scripts/agent.py`.
```bash
python scripts/agent.py --platform aws --tactic credential-access --detonate --cleanup
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Stratus Red Team GitHub | Source, releases, technique source | https://github.com/DataDog/stratus-red-team |
| Stratus Red Team docs | Technique catalog and lifecycle reference | https://stratus-red-team.cloud |
| Attack technique list | Full per-platform technique IDs | https://stratus-red-team.cloud/attack-techniques/list/ |
| MITRE ATT&CK Cloud | Tactic/technique reference for mapping | https://attack.mitre.org/matrices/enterprise/cloud/ |
| Atomic Red Team | Complementary endpoint emulation | https://github.com/redcanaryco/atomic-red-team |

## Detection-Validation Mapping

For purple-team value, pair each detonation with telemetry and detection it should trigger:

| Technique | Expected telemetry | Detection to validate |
|-----------|--------------------|-----------------------|
| `aws.credential-access.ec2-steal-instance-credentials` | CloudTrail use of role creds from non-EC2 IP | GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` |
| `aws.persistence.iam-create-admin-user` | `CreateUser` + `AttachUserPolicy` (AdministratorAccess) | CloudTrail/Sentinel rule on admin-policy attach |
| `aws.exfiltration.ec2-share-ebs-snapshot` | `ModifySnapshotAttribute` sharing to external account | GuardDuty `Exfiltration:EC2/...` / custom rule |
| `aws.discovery.ec2-enumerate-from-instance` | Burst of `Describe*` from instance role | Enumeration-burst detection |

After detonation, confirm alert fired end-to-end (source -> SIEM -> ticket). If it
did not, you have found coverage gap; document it before cleaning up.

## Cost and Safety Notes

- Some techniques provision billable resources (EC2 instances, EBS snapshots). Always
  run `stratus cleanup --all` and verify `stratus status` returns COLD.
- Never run Stratus with production credentials; use dedicated lab account/subscription.
- State directory `~/.stratus-red-team/` holds Terraform state — preserve it until
  cleanup completes, or you may strand resources.

## Lifecycle State Reference

| State | Meaning |
|-------|---------|
| COLD | No prerequisites provisioned; nothing to clean up |
| WARM | Prerequisites provisioned but not yet detonated |
| DETONATED | Attack actions performed; side effects present |

## Validation Criteria

- [ ] Stratus installed and `stratus list` returns technique catalog
- [ ] Target cloud identity confirmed via `sts get-caller-identity` / equivalent
- [ ] Technique inspected with `stratus show` before detonation
- [ ] Warmup completed and status shows WARM
- [ ] Detonation completed and status shows DETONATED
- [ ] Generated telemetry located in CloudTrail/GuardDuty/SIEM
- [ ] Detection rule confirmed to fire (or coverage gap documented)
- [ ] Technique reverted and re-detonated to confirm repeatability
- [ ] `stratus cleanup --all` run and status returns COLD for every technique
- [ ] No orphaned billable resources remain in account

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/emulating-cloud-attacks-with-stratus-red-team
