---
name: achieving-cmmc-level-2-compliance
description: 'Prepare a defense-contractor environment for CMMC Level 2 certification: scope CUI and FCI, implement the 110 NIST SP 800-171 Rev 2 security requirements across 14 families, compute the SPRS score with the DoD Assessment Methodology, manage a compliant POA&M, and ready the organization for a C3PAO assessment.'
subdomain: compliance-governance
facing: defense
mitre_attack:
- T1078
- T1190
- T1041
- T1048
- T1567
nist_csf:
- GV.OC-03
- GV.SC-01
- ID.AM-08
- ID.RA-05
- PR.AA-01
- PR.DS-01
upstream: achieving-cmmc-level-2-compliance@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Knowledge of **which contracts carry CUI** and CUI categories involved (check contract and DoD CUI Registry).
- Asset inventory and network diagram so you can define **CMMC assessment scope** before assessing controls.
- **NIST SP 800-171 Rev 2** requirements and **DoD Assessment Methodology** scoring weights.
- Documented **SSP** (its absence is itself failed requirement — 3.12.4).
- Identification of any **External Service Providers (ESPs)** / cloud services touching CUI, and whether they meet **FedRAMP Moderate (or equivalency)**.

## Workflow

### 1. Determine applicability and CUI categories
Confirm contract requires CMMC Level 2 (CUI present, not FCI). FCI-only contracts are **Level 1** (15 FAR 52.204-21 requirements). Identify CUI categories from contract and DoD CUI Registry.

### 2. Scope environment
Classify every asset into one of CMMC scoping categories:
- **CUI Assets** — process/store/transmit CUI (in scope, assessed against all applicable controls).
- **Security Protection Assets** — provide security to CUI environment (in scope).
- **Contractor Risk Managed Assets** — could but are not intended to handle CUI; managed by policy.
- **Specialized Assets** (IoT/OT, GFE, test equipment) — documented, limited assessment.
- **Out-of-Scope** — physically/logically isolated from CUI.

Minimize scope deliberately — smaller, well-segmented CUI enclave is far cheaper to certify than flat network.

### 3. Implement 110 requirements (NIST SP 800-171 Rev 2)
Work **14 families** (3.1–3.14). For each requirement, implement, then write **how** in SSP. High-leverage early wins: MFA (3.5.3), FIPS-validated cryptography (3.13.11), audit logging (3.3.x), access control + least privilege (3.1.x), and incident response (3.6.x).

### 4. Score with DoD Assessment Methodology (SPRS)
Start at **110** and subtract weighted value (**1, 3, or 5 points**) of each **unmet** requirement; partial credit applies to small number of controls (e.g., MFA, FIPS crypto). result is **SPRS score** (maximum 110; methodology floor is −203). Post score, SSP date, and assessment scope to **SPRS** (or eMASS for higher assessments).

### 5. Build compliant POA&M
Document every unmet requirement with owner, remediation, and milestone. **Constraints under CMMC rule:** **Conditional** status requires score of at least **80%** (≥ 88 of 110), only **POA&M-eligible** requirements may be deferred (highest-weighted security requirements must be fully met — verify eligibility against 32 CFR Part 170), and all POA&M items must be **closed within 180 days** to convert Conditional → **Final**.

### 6. Assess (self or C3PAO)
- **Level 1** and subset of Level 2 = annual **self-assessment** with affirmation in SPRS.
- **Level 2 (most CUI contracts)** = triennial **C3PAO** certification assessment.
- **Level 3** = DoD (DIBCAC) assessment on top of Level 2, adding SP 800-172 enhanced requirements.
Assessors evaluate each objective as **MET / NOT MET / N/A** with evidence (examine/interview/test). senior official files **annual affirmation** of continued compliance.

### 7. Maintain certification
Certification is valid **three years** with **annual affirmations**. Maintain SSP, re-score on change, keep evidence current, and feed significant changes back into assessment.

## Key Concepts

| Concept | Definition |
|---|---|
| FCI | Federal Contract Information — Level 1 protects it (FAR 52.204-21). |
| CUI | Controlled Unclassified Information — Level 2 protects it (NIST 800-171). |
| 110 requirements | SP 800-171 Rev 2 security requirements across 14 families. |
| SPRS | Supplier Performance Risk System — where 800-171 score is posted. |
| DoD Assessment Methodology | 1/3/5-point weighting used to compute score from 110. |
| C3PAO | CMMC Third-Party Assessment Organization — performs Level 2 certification. |
| POA&M | Plan of Action & Milestones — limited, must close in 180 days for Final status. |
| Conditional vs Final | Conditional = open POA&M (score ≥ 80%); Final = all controls met. |
| ESP | External Service Provider — must meet FedRAMP Moderate / equivalency for CUI. |
| Scoping categories | CUI / Security Protection / Contractor Risk Managed / Specialized / Out-of-Scope. |

## Tools & Systems

- **NIST SP 800-171 Rev 2** — 110 requirements (and 800-171A for assessment objectives).
- **DoD NIST SP 800-171 Assessment Methodology** — scoring weights.
- **32 CFR Part 170** (CMMC Program rule) and **48 CFR / DFARS 252.204-7021** (acquisition rule).
- **SPRS** — score posting; **SAM.gov** for registration.
- **SP 800-172 / 800-172A** — enhanced requirements for Level 3.
- **GRC / compliance tooling** — to manage SSP, POA&M, and evidence (e.g., Xacta, RegScale, FutureFeed-style trackers).

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/achieving-cmmc-level-2-compliance
