---
name: performing-ransomware-tabletop-exercise
description: Plans and facilitates tabletop exercises simulating ransomware incidents, using realistic scenarios based on threat actors like LockBit and ALPHV/BlackCat with injects covering double extortion and backup destruction, then evaluates responses against NIST CSF and CISA guidelines.
subdomain: ransomware-defense
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1486
- T1490
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
upstream: performing-ransomware-tabletop-exercise@54a7988 Apache-2.0, modified by wesh
---
Not for: as a substitute for technical controls testing. Tabletop exercises validate procedures and decision-making, not technical detection or prevention capabilities.

## Prerequisites

- Documented incident response plan (IRP) that participants should have read before exercise
- Identified exercise participants from: executive leadership, IT/security, legal, communications/PR, HR, operations, and external counsel
- Facilitator who is independent from IR team (to provide objective evaluation)
- Ransomware scenario designed with injects that escalate over multiple rounds
- Evaluation criteria aligned to NIST CSF Respond/Recover functions
- Conference room or virtual meeting for 2-4 hours with no interruptions

## Workflow

### Step 1: Design Exercise Scenario

Build realistic scenario based on current threat actor TTPs:

**Scenario Structure:**
```
Phase 1: Initial Detection (30 min)
  - SOC receives alert for suspicious process execution on file server
  - EDR detects Cobalt Strike beacon on 3 workstations
  - Inject: External threat intel report links C2 IP to LockBit affiliate
Phase 2: Escalation (30 min)
  - Ransomware executes on 40% of servers during overnight hours
  - Ransom note demands $2M in Bitcoin with 72-hour deadline
  - Inject: Attackers contact media claiming data theft of customer PII
Phase 3: Decision Points (45 min)
  - Backup assessment reveals immutable copies are intact but primary backups encrypted
  - Legal advises on breach notification timeline (72 hours GDPR, varies by US state)
  - Inject: Threat actor publishes sample of stolen data on leak site
Phase 4: Recovery and Communication (45 min)
  - Recovery time estimate: 5-7 days from immutable backups
  - Insurance carrier engages negotiation firm
  - Inject: Major customer threatens contract termination without update within 24 hours
```

**Scenario Variables to Customize:**
- Threat actor group and known TTPs
- Percentage of infrastructure encrypted
- Whether backups are intact, partially compromised, or fully destroyed
- Type of data exfiltrated (PII, PHI, financial, trade secrets)
- Applicable regulatory frameworks (GDPR, HIPAA, PCI DSS, SEC rules)
- Ransom amount and payment deadline

### Step 2: Prepare Exercise Materials

Create following documents for participants:

1. **Exercise Overview Briefing** - Ground rules, objectives, scope, and participants
2. **Situation Reports (SITREPs)** - One per phase, distributed as exercise progresses
3. **Inject Cards** - New information introduced at specific times to force decision-making
4. **Decision Point Worksheets** - Structured forms for documenting group decisions
5. **Evaluation Scorecard** - Criteria for assessing response quality

**Key Decision Points to Include:**
- When to activate incident response team
- Whether to shut down systems or contain selectively
- Whether to engage law enforcement (FBI IC3, CISA)
- Whether to pay ransom and under what conditions
- When and how to notify regulators, customers, and public
- How to prioritize system recovery order

### Step 3: Facilitate Exercise

**Facilitator Responsibilities:**
- Present each phase scenario and distribute SITREPs
- Introduce injects at predetermined times to increase pressure
- Ask probing questions to test decision-making reasoning
- Ensure all participant groups contribute (prevent IT from dominating)
- Document all decisions, rationales, and action items
- Track time management (many teams lose time on early phases)

**Probing Questions by Phase:**

Phase 1 - Detection:
- Who makes call to declare incident? What criteria trigger it?
- How do we determine scope of compromise from initial alerts?
- Do we have forensic capability to investigate or do we need external help?

Phase 2 - Escalation:
- What is our communication plan for employees? Do they know not to turn on affected machines?
- Have we isolated network to prevent further encryption?
- Who authorizes system shutdowns that impact business operations?

Phase 3 - Decision:
- Under what conditions would we consider paying ransom?
- What are legal obligations for notification at this point?
- How do we handle public leak of customer data?

Phase 4 - Recovery:
- What is recovery priority order? Is it documented or decided ad hoc?
- How long until critical business operations resume?
- What evidence preservation is required for law enforcement and insurance?

### Step 4: Evaluate and Score Responses

Score each functional area against defined criteria:

| Evaluation Area | Score (1-5) | Criteria |
|----------------|-------------|----------|
| Detection & Escalation | | Timely incident declaration, proper chain of command |
| Containment | | Network isolation, credential reset, scope assessment |
| Communication - Internal | | Employee notification, executive briefing, documented decisions |
| Communication - External | | Regulatory notification, customer communication, media response |
| Recovery Planning | | Backup verification, recovery priority, RTO tracking |
| Legal & Compliance | | Breach notification timelines, evidence preservation, law enforcement engagement |
| Business Continuity | | Manual operations, customer impact mitigation, revenue loss estimation |
| Payment Decision | | Structured framework, legal review, OFAC sanctions check |

### Step 5: Document Findings and Remediation Plan

Produce after-action report (AAR) within 5 business days:

**AAR Contents:**
1. Exercise overview and objectives
2. Scenario summary and injects
3. Key decisions made and rationale
4. Strengths observed
5. Gaps identified with severity rating
6. Remediation actions with owners and deadlines
7. Comparison to previous exercise results (if applicable)

## Key Concepts

| Term | Definition |
|------|------------|
| **Tabletop Exercise (TTX)** | Discussion-based exercise where participants walk through simulated incident scenario to test plans and procedures |
| **Inject** | New information introduced during exercise to change scenario and force additional decision-making |
| **SITREP** | Situation Report providing current status of simulated incident at each exercise phase |
| **After-Action Report (AAR)** | Post-exercise document capturing findings, gaps, strengths, and remediation actions |
| **Double Extortion** | Ransomware tactic where attackers both encrypt data and threaten to publish stolen data unless ransom is paid |
| **OFAC Check** | Verification that ransom payment recipient is not on US Treasury OFAC sanctions list, which would make payment illegal |

## Tools & Systems

- **CISA Tabletop Exercise Packages (CTEPs)**: Free scenario packages from CISA designed for critical infrastructure sectors
- **FEMA Homeland Security Exercise and Evaluation Program (HSEEP)**: Methodology for designing, conducting, and evaluating exercises
- **Immersive Labs**: Platform providing interactive cyber crisis simulations with real-time scoring
- **Tabletop Scenarios (from NCSC UK)**: Exercise in Box tool providing free guided tabletop exercises
- **Ransomware Readiness Assessment (CISA)**: Self-assessment tool for evaluating ransomware preparedness

## Ransomware Tabletop Exercise - After Action Report

**Exercise Date**: [Date]
**Facilitator**: [Name]
**Scenario**: [Brief description]
**Duration**: [Hours]
**Participants**: [Count by department]

### Exercise Objectives
1. [Objective] - Met / Partially Met / Not Met
2. [Objective] - Met / Partially Met / Not Met

### Key Decisions Log
| Time | Decision Point | Decision Made | Rationale | Assessment |
|------|---------------|--------------|-----------|------------|

### Strengths Observed
1. [Strength]

### Gaps Identified
| Gap | Severity | Affected Area | Current State | Desired State |
|-----|----------|--------------|---------------|---------------|

### Remediation Actions
| Action | Owner | Deadline | Priority | Status |
|--------|-------|----------|----------|--------|

### Comparison to Previous Exercise
| Area | Previous Score | Current Score | Trend |
|------|---------------|--------------|-------|
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-ransomware-tabletop-exercise
