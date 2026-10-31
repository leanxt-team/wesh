---
name: building-incident-response-playbook
description: Designs and documents structured incident response playbooks with step-by-step procedures per incident type, decision trees, escalation criteria, RACI matrices, and SOAR platform integration, aligned to NIST SP 800-61r3 and SANS PICERL.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1566
- T1190
- T1041
- T1078
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: building-incident-response-playbook@54a7988 Apache-2.0, modified by wesh
---
Not for: one-time ad hoc investigations; playbooks are reusable procedure documents, not case-specific reports.

## Prerequisites

- Organizational risk assessment identifying top incident scenarios by likelihood and impact
- NIST SP 800-61r3 or SANS PICERL framework adopted as organizational IR standard
- Asset inventory with business criticality ratings and data classification
- RACI chart defining roles: Incident Commander, SOC analysts, system administrators, legal, communications
- Existing detection capabilities inventory (SIEM rules, EDR detections, IDS signatures)
- SOAR platform access if building automated playbooks

## Workflow

### Step 1: Select and Scope Incident Type

Define specific scenario playbook will address:

- Identify top incident types based on organizational risk assessment and historical data
- Scope each playbook to single incident type for clarity (do not combine unrelated scenarios)
- Define trigger conditions that activate playbook

Common playbook types:
```
Priority Playbooks (build first):
1. Ransomware incident response
2. Phishing/credential compromise
3. Business email compromise
4. Malware infection
5. Data breach/exfiltration
6. DDoS attack
7. Insider threat
8. Account takeover
9. Web application compromise
10. Cloud infrastructure compromise
```

### Step 2: Define Playbook Structure

Every playbook should follow consistent structure:

```
PLAYBOOK TEMPLATE
━━━━━━━━━━━━━━━━
1. Playbook Metadata
   - Name, version, owner, last review date
   - Trigger conditions
   - Severity criteria
2. RACI Matrix
   - Who is Responsible, Accountable, Consulted, Informed for each step
3. Detection & Triage
   - How the incident is detected
   - Initial triage checklist
   - Severity classification criteria
4. Containment
   - Short-term containment actions
   - Long-term containment actions
   - Evidence preservation requirements
5. Eradication
   - Root cause identification
   - Malware/threat removal steps
   - Verification procedures
6. Recovery
   - System restoration steps
   - Validation criteria
   - Monitoring requirements post-recovery
7. Post-Incident
   - Lessons learned meeting trigger
   - Report template
   - Detection improvement actions
8. Communication
   - Internal notification matrix
   - External notification requirements (regulators, customers, law enforcement)
   - Status update cadence
9. Appendices
   - Tool-specific procedures
   - Contact lists
   - Evidence collection checklists
```

### Step 3: Write Decision Trees and Escalation Criteria

Define clear decision points with binary outcomes:

```
Detection Alert Received
├── Is the alert a true positive?
│   ├── YES → Classify severity
│   │   ├── P1 (Critical) → Page incident commander, begin containment immediately
│   │   ├── P2 (High) → Notify IR lead, begin investigation within 30 min
│   │   ├── P3 (Medium) → Queue for investigation within 4 hours
│   │   └── P4 (Low) → Document and investigate within 24 hours
│   └── NO → Document as false positive, tune detection rule
└── Cannot determine → Escalate to Tier 2 for deeper analysis
```

Escalation triggers:
- Any P1 incident: Immediate escalation to IR lead and CISO
- Data exfiltration confirmed: Legal counsel and privacy officer notified
- Customer data involved: Customer notification process activated
- Third-party involvement: Vendor security contact engaged
- Law enforcement needed: General counsel authorizes before contact

### Step 4: Define Specific Technical Procedures

Write tool-specific instructions for each step (not generic guidance):

```
CONTAINMENT - Endpoint Isolation via CrowdStrike:
1. Open Falcon Console > Hosts > Search for affected hostname
2. Click on the host > Host Details
3. Click "Contain Host" button in upper right
4. Confirm isolation (host will only communicate with CrowdStrike cloud)
5. Document containment action in incident ticket with timestamp
6. Verify containment: Host should show "Contained" status badge
CONTAINMENT - Block C2 Domain at DNS:
1. SSH to DNS server: ssh admin@dns-primary.corp.local
2. Add to block zone: echo "zone evil.com { type master; file /etc/bind/db.sinkhole; };" >> /etc/bind/named.conf.local
3. Reload DNS: rndc reload
4. Verify: dig @dns-primary evil.com (should resolve to sinkhole IP 10.0.0.99)
5. Document blocked domain in incident ticket
```

### Step 5: Integrate with SOAR Platform

Convert manual playbook steps into automated workflows:

- Map each playbook step to SOAR action (API call, script, human decision point)
- Define automation boundaries (what runs automatically vs. what requires analyst approval)
- Build enrichment automations for triage phase
- Create containment automations with approval gates for high-impact actions
- Configure notification automations for stakeholder communication

### Step 6: Test and Maintain Playbook

Validate playbook through exercises and maintain currency:

- Conduct tabletop exercises with IR team walking through playbook
- Perform live-fire exercises simulating incident type in test environment
- Review and update after every real incident that uses playbook
- Schedule quarterly reviews for accuracy of contact lists, tool procedures, and escalation paths
- Track playbook metrics: mean time to contain, mean time to resolve, false positive rate

## Key Concepts

| Term | Definition |
|------|------------|
| **Playbook** | Documented, repeatable set of procedures for responding to specific incident type |
| **Runbook** | More granular than playbook; step-by-step technical instructions for specific task within playbook |
| **RACI Matrix** | Responsibility assignment chart defining who is Responsible, Accountable, Consulted, and Informed for each activity |
| **Decision Tree** | Flowchart-based logic defining response path based on binary conditions at each decision point |
| **Escalation Criteria** | Predefined conditions that trigger notification of higher-level personnel or external parties |
| **SOAR Playbook** | Automated workflow in Security Orchestration, Automation, and Response platform executing playbook steps |

## Tools & Systems

- **Cortex XSOAR**: SOAR platform with visual playbook editor, 700+ integrations, and collaborative War Room
- **Splunk SOAR**: SOAR platform integrated with Splunk ES, drag-and-drop playbook builder with 2,800+ automated actions
- **TheHive**: Open-source incident response platform with case templates that function as playbook frameworks
- **Confluence / GitLab Wiki**: Documentation platforms for maintaining human-readable playbook documents with version control
- **Tines**: No-code security automation platform for building playbook workflows without programming

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/building-incident-response-playbook
