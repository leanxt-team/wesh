---
name: designing-adversary-engagement-with-mitre-engage
description: Plan, run, and measure an adversary engagement operation using the MITRE Engage framework so that deployed deception is driven by strategy instead of deployed ad hoc.
subdomain: deception-technology
facing: defense
mitre_attack:
- T1078
- T1083
- T1021
- T1552
- T1046
nist_csf:
- GV.RM-01
- ID.RA-01
- ID.IM-02
- DE.CM-01
- DE.AE-02
upstream: designing-adversary-engagement-with-mitre-engage@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with MITRE ATT&CK (tactics, techniques, and how to read technique page), because Engagement Activities are mapped to ATT&CK techniques they expose.
- Documented set of critical assets and understanding of which adversaries plausibly target them (threat model or prioritized threat actor list).
- Executive sponsorship and written legal review. Engagement operations interact with live adversaries and raise entrapment, evidence-handling, and liability questions; **never run engagement operation without legal sign-off.**
- Existing detection and response capability. Engage is additive strategy, not replacement for defense-in-depth; if defense-in-depth control fails, engagement keeps you in control rather than blind.
- Access to live matrix at https://engage.mitre.org/matrix/ for canonical Activity names and IDs.

## Workflow

Engage operations follow **10-Step Operational Process**. matrix is linear to read but cyclical to run — you continuously realign Activities toward your Goals as adversary reacts.

### 1. Confirm strategic fit (Prepare)
Decide where denial, deception, and adversary engagement fit in existing cyber strategy. The `Prepare` goal (strategic bookend, alongside `Understand`) defines inputs to operation. Document strategic goal in plain language, e.g. "reduce dwell time of insider threats around source-code repository" or "generate first-party CTI on actor targeting our VPN."

### 2. Define Engagement Goals and Operational Objectives
Select from three Engagement Goals. Goals set direction; **Operational Objectives** take measurable steps in that direction.

| Engagement Goal (EGO) | What it does | Example Operational Objective |
|---|---|---|
| Expose | Reveal adversary presence with high-fidelity, low-false-positive alerts | "Alert within 5 minutes of any touch on decoy credential" |
| Affect | Negatively change adversary's cost-value calculation (defender network only) | "Redirect adversary away from 3 unpatchable legacy hosts" |
| Elicit | Observe adversary to learn TTPs and produce CTI | "Obtain second-stage malware sample" or "identify ≥10 new indicators" |

Write objectives as falsifiable, time-bound statements. goal without objective is unmeasurable.

### 3. Build threat model and select Approaches
For each Goal, pick Engagement Approaches (EAP) that fit adversary you modeled:

- **Expose** → Collection, Detection
- **Affect** → Prevention, Direction, Disruption
- **Elicit** → Reassurance, Motivation

### 4. Map ATT&CK techniques to Engagement Activities
For each technique your target adversary uses, find Engage Activity that exposes weakness that technique creates. Example mappings:

| Adversary technique (ATT&CK) | Weakness exposed | Engage Activity (EAC) |
|---|---|---|
| T1078 Valid Accounts | Must test credentials | Decoy Credentials, Lures |
| T1083 File & Directory Discovery | Must enumerate files | Decoy Content, Pocket Litter |
| T1046 Network Service Discovery | Must scan network | Network Diversity, Decoy Systems |
| T1021 Remote Services | Must move laterally | Decoy Systems, Network Manipulation |
| T1552 Unsecured Credentials | Harvests secrets | Decoy Credentials, Artifact Diversity |

Pull authoritative Activity list and IDs from live matrix; Engage IDs use prefixes **SGO/EGO** (Goals), **SAP/EAP** (Approaches), and **SAC/EAC** (Activities).

### 5. Design engagement environment
Decide realism and isolation. Choose between standalone, connected, or integrated decoy environments (see D3FEND honeynet types in `references/standards.md`). Populate it with diverse, believable artifacts — Persona Creation, Pocket Litter, Artifact Diversity, Application Diversity — so environment survives adversary scrutiny.

### 6. Define gating criteria and rules of engagement
Document, before deployment: what adversary is allowed to reach, maximum blast radius, trigger for tear-down or hand-off to IR, evidence preservation steps, and who has authority to escalate. **Affect Activities are limited to defender's own network** — never act on infrastructure you do not own.

### 7. Deploy Activities
Implement selected Activities using tactical deployment skills (honeypots, honeytokens, canary tokens, decoy files). Instrument every artifact so touch produces telemetry routed to SOC.

### 8. Operate and observe
Run operation. Triage Expose alerts as high-fidelity (touch on decoy almost always means malicious or unauthorized activity). Feed observations back into Approach selection — realign Affect/Elicit Activities as adversary behaves.

### 9. Analyze (Understand)
The `Understand` goal (output bookend) turns observations into decisions: new detections for production, CTI for sharing, and validated or invalidated threat-model assumptions.

### 10. After-action and feedback
Score operation against Operational Objectives from Step 2. Capture what intel was gained, what Activities triggered, dwell time, and lessons learned. Update threat model and feed next cycle.

## Key Concepts

| Concept | Definition |
|---|---|
| Goal (SGO/EGO) | High-level outcome of operation. Prepare/Understand are strategic bookends; Expose/Affect/Elicit are engagement goals. |
| Approach (SAP/EAP) | method used to make progress toward Goal (e.g., Detection, Direction, Motivation). |
| Activity (SAC/EAC) | concrete denial/deception action deployed (e.g., Decoy Credentials, Network Manipulation). |
| Operate | default matrix view = Expose + Affect + Elicit, three engagement goals. |
| Operational Objective | measurable, time-bound target that operationalizes Goal. |
| Gating Criteria | Pre-defined boundaries and triggers that constrain operation's blast radius. |
| High-fidelity alert | alert from decoy that legitimate users have no reason to touch, yielding near-zero false positives. |
| Denial vs. Deception | Denial blocks adversary's access to real information; deception feeds plausible false information. |

## Tools & Systems

- **MITRE Engage Matrix and Starter Kit** (https://engage.mitre.org) — canonical Goals/Approaches/Activities, 10-Step Process, and operation-planning worksheets.
- **MITRE ATT&CK Navigator** — to lay out target adversary's techniques and overlay selected Engagement Activities.
- **MITRE D3FEND** — the `Deceive` tactic provides defensive countermeasure naming (Decoy Environment, Decoy Object, honeynet types) that complements Engage.
- **Deception platforms / open tooling** — OpenCanary, T-Pot, Cowrie (honeypots); Canarytokens, Thinkst Canary (honeytokens); to *implement* selected Activities.
- **SIEM/SOAR** — to route decoy telemetry to high-priority detections and automate Expose → IR hand-off.
- **CTI platform (MISP, OpenCTI)** — to store and share first-party intelligence produced under Elicit goal.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/designing-adversary-engagement-with-mitre-engage
