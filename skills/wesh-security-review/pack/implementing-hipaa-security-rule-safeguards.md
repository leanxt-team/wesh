---
name: implementing-hipaa-security-rule-safeguards
description: 'Implement the HIPAA Security Rule (45 CFR Part 164 Subpart C) to protect electronic protected health information (ePHI): conduct the required risk analysis, deploy the administrative, physical, and technical safeguards, handle required vs addressable implementation specifications, execute Business Associate Agreements, and stand up breach-notification readiness.'
subdomain: compliance-governance
facing: defense
mitre_attack:
- T1078
- T1566
- T1486
- T1530
- T1048
nist_csf:
- GV.OC-03
- GV.RM-01
- ID.RA-01
- ID.RA-05
- PR.DS-01
- PR.AA-01
- DE.CM-01
upstream: implementing-hipaa-security-rule-safeguards@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Clear determination of organization's **role** (covered entity vs business associate) and where ePHI lives, flows, and is stored (ePHI data map).
- **Asset inventory** of systems that create, receive, maintain, or transmit ePHI.
- Knowledge of current rule's structure (45 CFR §§164.302–318) and **required vs addressable** distinction.
- Awareness that **2025 NPRM** proposes significant changes (see Workflow step 7 and `references/standards.md`) — track but do not assume them as in force.

## Workflow

### 1. Conduct Security Risk Analysis (§164.308(a)(1)(ii)(A))
This is **required** and foundational. Inventory ePHI and systems, identify threats and vulnerabilities, assess current controls, determine likelihood and impact, and assign risk levels. (Pair with NIST 800-30 methodology and HHS's SRA Tool.) Output is documented, dated risk analysis — artifact OCR asks for first.

### 2. Implement Administrative Safeguards (§164.308)
Largest section. Includes **Security Management Process** (risk analysis, risk management, sanction policy, information-system activity review), assigned **security responsibility** (named Security Official), **workforce security**, **information access management**, **security awareness and training**, **security incident procedures**, **contingency planning** (data backup, disaster recovery, emergency-mode operation), **evaluation**, and **BAAs** with business associates.

### 3. Implement Physical Safeguards (§164.310)
**Facility access controls**, **workstation use** and **workstation security**, and **device and media controls** (disposal, media re-use, accountability, data backup and storage).

### 4. Implement Technical Safeguards (§164.312)
**Access control** (unique user ID, emergency access, automatic logoff, encryption/decryption), **audit controls**, **integrity** (mechanisms to authenticate ePHI), **person/entity authentication**, and **transmission security** (integrity controls + encryption).

### 5. Resolve "Required" vs "Addressable" specifications
Under current rule, each implementation specification is **Required** (must implement) or **Addressable** (assess whether reasonable and appropriate; if so implement, if not document why and implement equivalent alternative). **Addressable does not mean optional** — it means make and document risk-based decision.

### 6. Execute Business Associate Agreements (§164.314 / §164.308(b))
Every business associate that touches ePHI needs BAA binding it to safeguard ePHI, report incidents, and flow requirements to subcontractors. Maintain BAA inventory.

### 7. Track 2025 NPRM proposed changes (NOT yet final)
HHS OCR published NPRM (Jan 6, 2025) proposing to **remove required/addressable distinction** (make nearly all specifications required), and to mandate **MFA**, **encryption of ePHI at rest and in transit**, **asset inventory and network maps**, **vulnerability scans every 6 months**, **annual penetration testing**, **72-hour restoration of certain systems/data**, and **annual risk-analysis updates**. **These are proposals** — current rule remains in force until final rule is published and effective. Plan toward them, but comply with what is current.

### 8. Stand up breach-notification readiness (45 CFR §§164.400–414)
Define how you detect, assess (four-factor risk assessment), and report breaches of unsecured PHI: to **individuals** and **HHS** (and **media** for breaches affecting 500+ in state/jurisdiction), within required timelines. Encryption to NIST standards renders PHI "secured" and is safe harbor from breach notification.

### 9. Document everything (§164.316)
Maintain policies, procedures, and records of actions/decisions in writing, **retain for six years**, review periodically, and update in response to environmental or operational change.

## Key Concepts

| Concept | Definition |
|---|---|
| ePHI | Electronic protected health information — Security Rule's scope. |
| Covered entity | Health plan, clearinghouse, or provider doing electronic transactions. |
| Business associate | vendor that handles ePHI for covered entity; bound by BAA. |
| Risk analysis | Required, documented assessment of risks to ePHI (§164.308(a)(1)(ii)(A)). |
| Required vs addressable | Must-implement vs risk-based-decision implementation specifications. |
| Administrative / Physical / Technical safeguards | §164.308 / §164.310 / §164.312. |
| BAA | Business Associate Agreement — contractually binds vendors to safeguard ePHI. |
| Breach (unsecured PHI) | Triggers notification under §§164.400–414; encryption is safe harbor. |
| OCR | HHS Office for Civil Rights — enforces HIPAA. |
| Six-year retention | Documentation retention requirement (§164.316). |

## Tools & Systems

- **45 CFR Part 164 Subpart C** — Security Rule text (and Subpart D, Breach Notification).
- **HHS Security Risk Assessment (SRA) Tool** — free guided risk analysis.
- **NIST SP 800-66 Rev 2** — implementing HIPAA Security Rule (NIST guidance, maps to 800-53).
- **NIST SP 800-30** — risk-assessment methodology to ground SRA.
- **GRC / compliance platforms** — to manage policies, BAA inventory, and evidence.
- **Encryption / MFA / SIEM / audit-logging tooling** — to satisfy technical safeguards and proposed mandates.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-hipaa-security-rule-safeguards
