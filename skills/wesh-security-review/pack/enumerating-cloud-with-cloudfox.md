---
name: enumerating-cloud-with-cloudfox
description: Run CloudFox's read-only Describe/List/Get enumeration (all-checks, role-trusts, secrets, endpoints, and permissions commands) to map AWS and Azure attack paths and surface exploitable misconfigurations.
subdomain: cloud-security
facing: config
mitre_attack:
- T1526
nist_csf:
- ID.AM-03
upstream: enumerating-cloud-with-cloudfox@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- CloudFox installed:
  ```bash
  # Homebrew
  brew install cloudfox
  # Go (1.21+)
  go install github.com/BishopFox/cloudfox@latest
  # or download a release binary from GitHub and chmod +x
  ```
- Valid cloud credentials in scope:
  ```bash
  # AWS — configure a named profile and verify
  aws configure --profile assess
  aws sts get-caller-identity --profile assess
  # Azure
  az login
  az account show
  ```
- Signed authorization / Rules of Engagement defining in-scope accounts
- `awscli` (AWS) and/or `azure-cli` (Azure) installed for credential setup and follow-up

## MITRE ATT&CK Mapping

| ID | Name | Use in this skill |
|----|------|-------------------|
| T1526 | Cloud Service Discovery | CloudFox enumerates available cloud services and resources in account |
| T1580 | Cloud Infrastructure Discovery | `inventory`, `instances`, `buckets` map infrastructure footprint |
| T1087.004 | Account Discovery: Cloud Account | `principals`, `access-keys` enumerate cloud identities |
| T1069.003 | Permission Groups Discovery: Cloud Groups | `permissions`, `iam-simulator`, `role-trusts` reveal entitlements |
| T1538 | Cloud Service Dashboard | Aggregated situational-awareness reporting across services |

## Workflow

### 1. Confirm identity and run all AWS checks
```bash
aws sts get-caller-identity --profile assess
cloudfox aws --profile assess all-checks -o ./loot
```

### 2. Inventory account footprint
```bash
cloudfox aws --profile assess inventory
```

### 3. Find internet-reachable endpoints and exposed instances
```bash
cloudfox aws --profile assess endpoints
cloudfox aws --profile assess instances
```

### 4. Enumerate IAM principals, permissions, and role-trust attack paths
`role-trusts` is key lateral-movement primitive — it shows who can assume what.
```bash
cloudfox aws --profile assess principals
cloudfox aws --profile assess permissions
cloudfox aws --profile assess role-trusts
cloudfox aws --profile assess access-keys
```

### 5. Hunt for exposed secrets
```bash
cloudfox aws --profile assess secrets
```

### 6. Enumerate storage, registries, and serverless
```bash
cloudfox aws --profile assess buckets
cloudfox aws --profile assess ecr
cloudfox aws --profile assess lambda
cloudfox aws --profile assess route53
```

### 7. Use IAM simulator to confirm what principal can do
```bash
cloudfox aws --profile assess iam-simulator
```

### 8. Enumerate Azure
CloudFox Azure works against subscriptions the `az` session can see.
```bash
cloudfox azure inventory --outdir ./azure-loot
cloudfox azure rbac
cloudfox azure storage
cloudfox azure vms
```

### 9. Triage loot
CloudFox writes per-command CSV/TXT plus a `loot` directory of pivot commands.
```bash
ls -R ./loot/cloudfox-output/
# Loot files contain ready-to-run follow-ups, e.g. aws s3 ls / ssm start-session lines
```
See `scripts/agent.py` to run curated set of commands and summarize output files.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| CloudFox GitHub | Source, releases, full command list | https://github.com/BishopFox/cloudfox |
| CloudFox docs/wiki | Per-command output explanations | https://github.com/BishopFox/cloudfox/wiki |
| Bishop Fox CloudFox blog | Design and usage walkthrough | https://bishopfox.com/blog/introducing-cloudfox |
| AWS CLI reference | Follow-up exploitation commands | https://docs.aws.amazon.com/cli/latest/reference/ |
| Pacu | Active exploitation after enumeration | https://github.com/RhinoSecurityLabs/pacu |

## OPSEC and Detection Considerations

CloudFox is read-only, but its enumeration is far from silent. Each command issues
many `Describe*`/`List*`/`Get*` API calls in short burst, visible
to defenders:

- **CloudTrail** records every read call. spike of `iam:ListUsers`, `iam:ListRoles`,
  `secretsmanager:ListSecrets`, `ec2:DescribeInstances`, and `sts:GetCallerIdentity`
  from one principal within seconds is strong enumeration signal.
- **GuardDuty** finding types e.g. `Discovery:IAMUser/AnomalousBehavior` and
  `Discovery:S3/MaliciousIPCaller` can fire on this burst pattern.
- Defenders should baseline normal API-call rates per principal and alert on
  enumeration bursts, especially from new IPs/ASNs or newly created credentials.

For authorized assessment, document source IP and timestamp of CloudFox runs
so blue team can correlate, and prefer running from in-scope, attributable host.

## Recommended Operator Workflow

1. Run `all-checks` once to populate full output directory.
2. Open `role-trusts` first — it reveals assume-role graph for lateral movement.
3. Cross-reference `secrets` and `env-vars` for credentials that unlock new principals.
4. Use `endpoints` + `instances` to map externally reachable attack surface.
5. Feed confirmed assume-role / privesc candidates into Pacu for active exploitation.

## High-Value Command Reference

| Command | Why it matters |
|---------|----------------|
| `all-checks` | Runs full enumeration battery with defaults |
| `role-trusts` | Maps assume-role paths — core for lateral movement/privesc |
| `endpoints` | Surfaces internet-reachable attack surface |
| `secrets` | Exposes credentials in Secrets Manager / SSM |
| `permissions` | Lists effective IAM permissions per principal |
| `instances` | EC2 with IPs and attached instance-profile roles |
| `access-keys` | Active access keys (potential credential targets) |

## Validation Criteria

- [ ] CloudFox installed and runs `cloudfox aws --help`
- [ ] Cloud credentials confirmed via `sts get-caller-identity` / `az account show`
- [ ] `all-checks` completed and output directory populated
- [ ] Internet-reachable endpoints and instances identified
- [ ] IAM principals, permissions, and role-trusts enumerated
- [ ] Exposed secrets located and documented
- [ ] Azure enumeration run (if Azure in scope)
- [ ] Loot files triaged for pivot opportunities
- [ ] Findings exported to structured directory for reporting
- [ ] Enumeration confirmed to stay within authorized scope

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/enumerating-cloud-with-cloudfox
