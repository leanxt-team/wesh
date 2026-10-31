---
name: managing-third-party-vendor-risk
description: 'Build and run a third-party/vendor risk management (TPRM) program aligned to NIST SP 800-161 C-SCRM: inventory and tier vendors, issue SIG/CAIQ questionnaires, review SOC 2/ISO 27001 evidence, set contractual right-to-audit clauses, monitor vendors continuously, and offboard securely.'
subdomain: compliance-governance
facing: defense
mitre_attack:
- T1199
- T1195
- T1078
- T1190
- T1567
nist_csf:
- GV.SC-01
- GV.SC-04
- GV.SC-06
- GV.SC-07
- ID.RA-05
- GV.OC-03
upstream: managing-third-party-vendor-risk@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- A **vendor inventory** (who you use, for what, and what data/access each has).
- Defined **risk-tiering model** (criteria and thresholds) agreed with business.
- Access to standardized **questionnaires** (Shared Assessments **SIG**, CSA **CAIQ**) and way to collect evidence.
- Clarity on your own **regulatory obligations** that flow down to vendors (e.g., HIPAA BAAs, CMMC flowdown, GDPR processor terms, PCI).
- Stakeholders identified: procurement, legal, security, data owner, and business sponsor.

## Workflow

### 1. Inventory and classify vendors
Catalog every third party and capture: data sensitivity handled, type of access (network, physical, none), business criticality, and regulatory scope. You cannot manage what you have not inventoried — shadow vendors are common blind spot.

### 2. Tier by inherent risk
Score each vendor on inherent-risk factors (data sensitivity, access, criticality, regulatory scope, spend/concentration) and assign **tier** (e.g., Critical / High / Moderate / Low). tier drives **how deep** assessment goes and **how often** you reassess. payroll processor with PII and system access is not same risk as stock-photo subscription.

### 3. Run tier-appropriate due diligence
- **Critical/High:** full **SIG** (or SIG Core), request **SOC 2 Type II** and/or **ISO 27001**, recent **pen-test** summary, and evidence of incident-response capability. Consider assessor call.
- **Moderate:** **SIG Lite** or **CAIQ**, plus key attestations.
- **Low:** lightweight questionnaire / self-attestation.

### 4. Review evidence critically
Don't collect — **read**:
- **SOC 2 Type II:** check scope, Trust Services Criteria covered, audit **period** (not date), and especially **exceptions/deviations** and any qualified opinion. clean cover page can hide noted exceptions.
- **ISO 27001:** confirm **scope statement** and Statement of Applicability cover service you're buying.
- **CAIQ:** look for "no" answers and CCM domains left blank.
- **Pen-test:** age, scope, and whether highs/criticals were remediated.

### 5. Identify gaps and decide
Compare findings against your control requirements. For each gap: accept, require remediation (with date), add compensating control on your side, or walk away. Record **residual risk** and risk-owner decision.

### 6. Codify in contract / DPA
Bake requirements into agreement: security control obligations, **breach-notification timeline**, data-handling and return/destruction terms, **right-to-audit / right to assessment evidence**, subcontractor (Nth-party) flowdown, and liability/insurance. Contracts are where TPRM gets teeth.

### 7. Monitor continuously
Tiering is not one-time gate. For higher tiers: periodic reassessment, **security-ratings** feeds, breach/news monitoring, certificate-expiry tracking, and watching for material changes (acquisition, region change, new subprocessors). Re-tier on change.

### 8. Manage Nth-party and concentration risk
Map critical **fourth parties** (your vendor's key subprocessors) and watch for **concentration** (many vendors riding on same upstream provider) — single upstream outage or breach can hit your whole portfolio at once.

### 9. Offboard securely
On termination: revoke access and credentials, confirm **data return or certified destruction**, remove integrations/API keys, and update inventory. Un-offboarded vendors are standing risk.

## Key Concepts

| Concept | Definition |
|---|---|
| Inherent risk | Risk vendor poses before controls — drives tiering. |
| Residual risk | Risk remaining after vendor's (and your) controls. |
| Vendor tier | Risk band (Critical/High/Moderate/Low) setting assessment depth and cadence. |
| SIG | Shared Assessments Standardized Information Gathering questionnaire (full / Lite / Core). |
| CAIQ | CSA Consensus Assessments Initiative Questionnaire (maps to Cloud Controls Matrix). |
| SOC 2 Type II | Attestation on control design **and** operating effectiveness over period. |
| Right to audit | Contractual right to assess vendor or obtain assessment evidence. |
| Nth-party / fourth-party | Your vendor's vendors (and beyond) — indirect supply-chain risk. |
| Concentration risk | Many vendors depending on same upstream provider. |
| C-SCRM | Cybersecurity Supply Chain Risk Management (NIST SP 800-161). |

## Tools & Systems

- **NIST SP 800-161 Rev 1** — Cybersecurity Supply Chain Risk Management practices.
- **NIST CSF 2.0 — GV.SC** — supply-chain risk-management category (program backbone).
- **Shared Assessments SIG** and **CSA CAIQ / STAR registry** — standardized questionnaires.
- **SOC 2 / ISO 27001 / PCI AOC / pen-test reports** — vendor evidence.
- **Security-ratings services** (e.g., BitSight/SecurityScorecard-style) — continuous external signal.
- **TPRM platforms** — OneTrust, ProcessUnity, Prevalent, ServiceNow VRM, etc., to manage workflow and inventory.
- **GDPR DPA / HIPAA BAA / CMMC flowdown** — regulatory contract instruments.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/managing-third-party-vendor-risk
