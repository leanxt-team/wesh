---
name: executing-nist-rmf-authorization-to-operate
description: 'Drive a federal system through the NIST Risk Management Framework (SP 800-37 Rev 2) to an Authorization to Operate (ATO): Prepare, Categorize (FIPS 199), Select a control baseline (FIPS 200 / SP 800-53 Rev 5), Implement, Assess (SP 800-53A), Authorize, and Monitor continuously.'
subdomain: compliance-governance
facing: defense
mitre_attack:
- T1078
- T1190
- T1068
- T1210
- T1486
nist_csf:
- GV.OC-03
- GV.RM-01
- ID.AM-08
- ID.RA-05
- PR.IR-01
upstream: executing-nist-rmf-authorization-to-operate@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Defined **system** and **authorization boundary** (what's in, what's inherited, what's leveraged service).
- Identified **Authorizing Official (AO)**, **System Owner**, and **ISSO**.
- Information types system handles (use **SP 800-60** to map them to impact levels).
- For cloud: provider's **Customer Responsibility Matrix (CRM)** and any inherited/leveraged ATO.
- Access to assessment evidence sources (config, scans, policies) for Assess step.

## Workflow

NIST SP 800-37 Rev 2 defines **seven steps**. Prepare is foundation; rest run in order and then loop through Monitor.

### 0/1. Prepare (organization and system level)
Establish context: roles (AO, SO, ISSO, assessor), risk-management strategy and tolerance (ties to SP 800-39), control baseline strategy, common controls available for inheritance, and system's mission/business context. Define **authorization boundary** precisely — scope creep here inflates whole package.

### 2. Categorize (FIPS 199 + SP 800-60)
Determine impact level for **confidentiality, integrity, and availability** for each information type, then take **high-water mark** across three to set overall system categorization: **Low**, **Moderate**, or **High**. Document in SSP. This single decision drives entire control baseline.

### 3. Select (FIPS 200 + SP 800-53 Rev 5 + SP 800-53B)
Start from SP 800-53B baseline matching categorization (Low/Moderate/High). Then **tailor**: apply scoping guidance, select compensating controls where needed, and assign values to organization-defined parameters. Add overlays (e.g., privacy, FedRAMP). Record tailored set and rationale in SSP. Identify which controls are **common (inherited)**, **system-specific**, or **hybrid**.

### 4. Implement
Deploy selected controls and **document how each is implemented** in SSP — implementation statement, not "yes." This is artifact assessors read first; vague statements generate findings.

### 5. Assess (SP 800-53A Rev 5)
Independent assessor evaluates controls using **examine / interview / test** methods against assessment objectives. Findings of "other than satisfied" become weaknesses. Output is **Security Assessment Report (SAR)**. Remediate what you can before authorization; rest flows to POA&M.

### 6. Authorize
Assemble **authorization package**: SSP + SAR + POA&M (plus supporting artifacts). AO reviews **residual risk** and renders decision:
- **ATO** — authorized, typically with defined term and ConMon expectation.
- **Conditional / cATO** — authorized subject to conditions or operating under approved ongoing-authorization model.
- **Denial / DATO** — risk too high; system may not operate.

Decision and its rationale are captured in **authorization decision document**.

### 7. Monitor (continuous monitoring)
Authorization is not one-time gate. Maintain ongoing posture: track control effectiveness, ingest scan/config drift, update SSP on change, work POA&M to closure, report per ConMon plan, and feed significant changes back into reassessment. Mature programs move from periodic re-ATO to **ongoing authorization**.

## Key Concepts

| Concept | Definition |
|---|---|
| Authorization boundary | set of components, data flows, and inherited services covered by authorization. |
| FIPS 199 categorization | Low/Moderate/High per C/I/A; overall = high-water mark across three. |
| Control baseline | SP 800-53B starting control set for categorization, before tailoring. |
| Tailoring | Adjusting baseline via scoping, compensating controls, and parameter values. |
| Common / inherited control | control provided by another entity (e.g., platform) and inherited by system. |
| SSP | System Security Plan — describes system, boundary, and how each control is implemented. |
| SAR | Security Assessment Report — assessor's findings on control effectiveness. |
| POA&M | Plan of Action & Milestones — tracked weaknesses with owners and remediation dates. |
| ATO / cATO / DATO | Authorize / conditional (ongoing) / denial of authorization to operate. |
| Authorizing Official (AO) | senior official who accepts residual risk and signs authorization. |
| ConMon | Continuous monitoring — ongoing control-effectiveness and risk tracking post-ATO. |

## Tools & Systems

- **NIST SP 800-37 Rev 2** — RMF process (7 steps).
- **FIPS 199 / FIPS 200 / SP 800-60** — categorization and minimum requirements.
- **NIST SP 800-53 Rev 5 / 800-53B** — control catalog and baselines.
- **NIST SP 800-53A Rev 5** — assessment procedures (examine/interview/test).
- **OSCAL** — machine-readable SSP/SAR/POA&M (NIST's authorization-document format).
- **eMASS** (DoD) / **FedRAMP** templates — package management and submission.
- **GRC platforms** — Xacta, ServiceNow, RegScale, etc., to manage package and ConMon.
- **NIST CSF 2.0** — cross-walks to communicate RMF posture in framework terms.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/executing-nist-rmf-authorization-to-operate
