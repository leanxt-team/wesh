---
name: conducting-social-engineering-pretext-call
description: Plan and execute authorized vishing (voice phishing) pretext calls to assess employee susceptibility to social engineering and evaluate security awareness controls.
subdomain: red-teaming
facing: config
mitre_attack:
- T1598.004
- T1566.004
- T1589
- T1591
- T1598
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: conducting-social-engineering-pretext-call@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Written authorization specifying social engineering scope and boundaries
- List of approved target employees (usually provided by client)
- OSINT research on targets and organization
- Spoofed caller ID capability (authorized for testing)
- Call recording equipment (with legal consent as required)
- Pretext scenarios approved by client

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1566.004 | Phishing: Voice | Initial Access |
| T1598 | Phishing for Information | Reconnaissance |
| T1598.003 | Phishing for Information: Spearphishing Voice | Reconnaissance |
| T1589 | Gather Victim Identity Information | Reconnaissance |
| T1591 | Gather Victim Org Information | Reconnaissance |

## Phase 1: OSINT and Target Research

```bash
# LinkedIn employee enumeration
theHarvester -d targetcorp.com -b linkedin -l 200

# Company org chart and employee roles
# Review LinkedIn, corporate website "About Us" / "Team" pages

# Technology stack identification
# Check job postings for technology references (VPN vendor, email, helpdesk tool)

# Phone system identification
# Call main line, note IVR options, department names, extension patterns
```

Key intelligence to gather:
- Internal helpdesk phone number and procedures
- IT department names and staff
- VPN/remote access vendor (Cisco AnyConnect, Fortinet, Pulse Secure)
- Corporate email format (first.last, flast, etc.)
- Recent events (mergers, office moves, system upgrades)
- Employee names, titles, departments

## Phase 2: Pretext Development

### Common Pretext Scenarios

**IT Helpdesk Impersonation (Most Effective):**
> "Hi, this is [name] from IT Service Desk. We're migrating everyone to new VPN client this week, and I see your account hasn't been updated yet. I need to verify your current credentials to ensure migration goes smoothly. Can you confirm your username and current password?"

**Vendor/Contractor:**
> "Hi, I'm [name] from [known vendor]. We're doing emergency patch deployment for [product] and I need remote access to your system. Could you help me connect via TeamViewer?"

**Executive Assistant (Authority):**
> "This is [name] calling on behalf of [CFO name]. [He/She] needs urgent wire transfer processed for deal that's closing today. I'll email you details, but we need this done in next hour."

**Building/Facilities:**
> "Hi, this is [name] from facilities management. We're updating badge access system this weekend. I need to confirm your employee ID and current badge number so your access isn't interrupted."

### Pretext Checklist

- [ ] Is pretext believable for this organization?
- [ ] Does it create appropriate urgency without being threatening?
- [ ] Does it align with OSINT findings (real dept names, real systems)?
- [ ] Does it have plausible reason for requesting information?
- [ ] Is there fallback if target pushes back?
- [ ] Has client approved this specific pretext?

## Phase 3: Call Execution

### Call Structure

1. **Introduction** (10 seconds): State name, department, reason for calling
2. **Building rapport** (30 seconds): Reference something real (recent event, shared context)
3. **Authority establishment** (20 seconds): Reference manager name, ticket number, urgency
4. **Information request** (30 seconds): Ask for target information naturally
5. **Handling objections**: If challenged, respond calmly with prepared answers
6. **Closing** (10 seconds): Thank them, leave no suspicion

### Objection Handling

| Objection | Response |
|---|---|
| "Can I call you back?" | "Of course, call main helpdesk line and ask for [name]. But this needs to be done by EOD." |
| "I need to verify this" | "Absolutely, I appreciate your diligence. You can check with [manager name]." |
| "I was told never to give passwords" | "You're right, and normally we wouldn't ask. This is special case because [reason]. I can have my manager call you." |
| "What's your employee ID?" | Pivot: "It's [made-up ID]. Listen, I have 50 more people to call today. Can we just get this done?" |
| "I'll email IT instead" | "Sure, but system migration happens tonight. If it's not done by then..." |

## Phase 4: Data Collection and Metrics

Track following for each call:

| Metric | Description |
|---|---|
| Target Name | Employee called |
| Department | Target's department |
| Date/Time | When call was made |
| Duration | Length of call |
| Pretext Used | Which scenario |
| Information Obtained | What was disclosed |
| Credential Disclosed | Yes/No (and type) |
| Verification Attempted | Did target try to verify caller? |
| Reported to Security | Did target report call? |
| Social Engineering Score | 1-5 susceptibility rating |

## Phase 5: Reporting

### Success Metrics

| Metric | Target | Result |
|---|---|---|
| Credential Disclosure Rate | <10% | XX% |
| Sensitive Info Disclosure Rate | <20% | XX% |
| Verification Rate | >80% | XX% |
| Security Reporting Rate | >50% | XX% |

## Ethical and Legal Considerations

1. **Always obtain written authorization** before conducting vishing tests
2. **Never use threatening language** or create genuine fear
3. **Document consent** and legal requirements for call recording
4. **Protect disclosed credentials** - immediately report to client
5. **Debrief targets** after engagement if client approves
6. **Never publicly identify** specific employees who failed
7. **Comply with telecommunications laws** in your jurisdiction

## References

- Verizon DBIR 2025: 74% of breaches involve human element
- MITRE ATT&CK T1598: https://attack.mitre.org/techniques/T1598/
- Social Engineering Penetration Testing by Gavin Watson (Syngress)
- Art of Deception by Kevin Mitnick (Wiley)
- NIST SP 800-50: Building Information Technology Security Awareness and Training Program

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-social-engineering-pretext-call
