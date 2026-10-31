---
name: conducting-cyber-risk-assessment-with-nist-800-30
description: 'Conduct a defensible cybersecurity risk assessment using the NIST SP 800-30 Rev 1 methodology: prepare scope and a risk model, identify threat sources and threat events, identify vulnerabilities and predisposing conditions, determine likelihood and impact, compute risk, and communicate results as a prioritized risk register.'
subdomain: compliance-governance
facing: defense
mitre_attack:
- T1566
- T1078
- T1190
- T1486
- T1021
nist_csf:
- GV.RM-01
- ID.RA-01
- ID.RA-03
- ID.RA-04
- ID.RA-05
upstream: conducting-cyber-risk-assessment-with-nist-800-30@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Inventory of in-scope assets, systems, and information types they handle (system boundary defined).
- Access to threat intelligence (internal incident history, sector ISAC feeds, MITRE ATT&CK) to ground threat-event likelihood in observed behavior.
- Vulnerability data (scan results, pen-test findings, configuration/architecture review) for in-scope systems.
- Business context: which missions/processes systems support, and what impact to confidentiality, integrity, or availability would mean in business terms.
- Agreement on **risk model and scales** before scoring, so results are comparable and repeatable (see `references/standards.md`).
- Familiarity with three-tier risk-management context from NIST SP 800-39 (organization, mission/business process, information system).

## Workflow

NIST SP 800-30 Rev 1 defines four steps. Steps 1 and 4 bookend assessment; Step 2 is analytic core.

### 1. Prepare for assessment
Define and document:
- **Purpose** (e.g., support authorization decision, inform control selection, satisfy ISO 6.1.2).
- **Scope** — organizational tier (Tier 1/2/3), systems, and time horizon.
- **Assumptions and constraints** (e.g., assume external adversarial threat with moderate capability).
- **Information sources** — threat, vulnerability, and impact inputs.
- **Risk model and analytic approach** — factors (threat source, threat event, vulnerability, likelihood, impact) and scales (qualitative Low–High, or semi-quantitative 0–10). Lock these now.

### 2. Conduct assessment
Work through analytic tasks in order. 800-30 appendices provide reference taxonomies (D–I).

**2a. Identify threat sources (Appendix D).** Classify by type: **Adversarial** (individuals, groups, nation-states — characterize capability, intent, targeting), **Accidental** (user error), **Structural** (equipment/software failure), **Environmental** (natural disasters, infrastructure outages).

**2b. Identify threat events (Appendix E).** specific actions source could take (e.g., "adversary exfiltrates credentials via phishing then moves laterally"). Map adversarial events to MITRE ATT&CK techniques for traceability.

**2c. Identify vulnerabilities and predisposing conditions (Appendix F).** Weaknesses (missing MFA, unpatched service) and conditions that make exploitation more or less likely (internet exposure, flat network, lack of segmentation).

**2d. Determine likelihood (Appendix G).** Assess likelihood that threat event is *initiated* (adversarial) or *occurs* (non-adversarial), and likelihood it results in adverse impact given vulnerabilities. Combine into overall likelihood on agreed scale.

**2e. Determine impact (Appendix H).** Magnitude of harm if event succeeds — to operations, assets, individuals, other organizations, or nation. Express against agreed scale and in business terms.

**2f. Determine risk (Appendix I).** Risk is function of likelihood and impact. Plot each threat event on risk matrix (e.g., likelihood × impact → Low … High). Record risk level, contributing factors, and uncertainty/assumptions.

### 3. Communicate and share results
Produce **risk register** and executive briefing. For each risk: threat event, affected assets, likelihood, impact, risk level, key contributing vulnerabilities, and recommended treatment. Rank by risk level so decision-makers see top risks first.

### 4. Maintain assessment
Risk is not static. Define refresh cadence and triggers that force re-assessment (new system, major architecture change, significant incident, new threat intel). Track risk-acceptance decisions and treatment progress over time.

### 5. Drive treatment decisions
Hand ranked register to risk owners. For each risk choose treatment — **mitigate** (add/strengthen controls), **transfer** (insurance, contractual), **avoid** (stop activity), or **accept** (document residual risk with authorizing signature). Re-score residual risk after planned controls to show post-treatment position.

## Key Concepts

| Concept | Definition |
|---|---|
| Threat source | cause of threat event: adversarial, accidental, structural, or environmental. |
| Threat event | specific action or occurrence that could cause harm (mapped to ATT&CK for adversarial cases). |
| Vulnerability | weakness that threat event can exploit. |
| Predisposing condition | condition that increases or decreases likelihood of adverse impact (e.g., internet exposure). |
| Likelihood | chance threat event initiates/occurs *and* results in adverse impact. |
| Impact | magnitude of harm if event succeeds. |
| Risk | function of likelihood and impact; expected harm to organization. |
| Inherent vs residual risk | Risk before vs after planned/implemented controls. |
| Risk tolerance / appetite | level of risk leadership is willing to accept. |
| Risk register | prioritized record of risks, scores, owners, and treatments. |

## Tools & Systems

- **NIST SP 800-30 Rev 1** — methodology and Appendices D–I taxonomies (threat sources, events, vulnerabilities, likelihood, impact, risk).
- **NIST SP 800-39** — enterprise risk-management context (three tiers).
- **MITRE ATT&CK** — to enumerate and ground adversarial threat events in observed TTPs.
- **Vulnerability scanners / pen-test reports** — empirical vulnerability input.
- **Threat intel sources** — sector ISACs, vendor feeds, internal incident history for likelihood grounding.
- **GRC / risk-register tooling** — spreadsheet, or platforms e.g. ServiceNow GRC, Archer, OneTrust, to store and track register.
- **FAIR** (optional) — quantitative model if leadership wants risk expressed in dollar ranges rather than qualitative bands.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-cyber-risk-assessment-with-nist-800-30
