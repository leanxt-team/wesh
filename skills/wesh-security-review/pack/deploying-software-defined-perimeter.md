---
name: deploying-software-defined-perimeter
description: Deploys a Software-Defined Perimeter per the CSA v2.0 specification, configuring Single Packet Authorization, mutual TLS, and SDP controller/gateway components to enforce zero trust network access.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1133
- T1078
- T1021
- T1046
- T1190
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: deploying-software-defined-perimeter@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Understanding of zero trust principles (NIST SP 800-207)
- Knowledge of CSA Software-Defined Perimeter specification
- Familiarity with PKI and mutual TLS authentication
- Experience with network security architecture

## Prerequisites

- Familiarity with zero trust architecture concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Architecture

### SDP Components (CSA Specification)

```
┌─────────────────────┐
│ SDP Controller       │
│ - Authentication     │
│ - Authorization      │
│ - Policy management  │
│ - Key management     │
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    │             │
    v             v
┌────────┐  ┌────────────┐
│ IH     │  │ AH         │
│(Client)│  │(Gateway)   │
│        │  │            │
│ SPA    │──│ Protected  │
│ mTLS   │  │ Resources  │
└────────┘  └────────────┘
IH = Initiating Host (User Device)
AH = Accepting Host (Application Gateway)
SPA = Single Packet Authorization
```

### SDP Deployment Models
1. **Client-to-Gateway**: User device connects through SDP gateway to backend applications
2. **Client-to-Server**: Direct connection between user and application server
3. **Server-to-Server**: Workload-to-workload communication through SDP
4. **Gateway-to-Gateway**: Site-to-site connectivity replacing traditional VPN tunnels

## Key Concepts

### Single Packet Authorization (SPA)
SPA is network security mechanism where SDP gateway drops all TCP/UDP packets by default. cryptographically signed single packet must be sent before any connection is established. gateway validates SPA packet, and only then opens temporary port for authenticated session. This makes gateway invisible to port scanners.

### Mutual TLS (mTLS)
After SPA validation, both client and server authenticate each other using X.509 certificates. This bidirectional authentication prevents man-in-the-middle attacks and ensures both endpoints are verified.

### Dynamic Provisioning
SDP connections are provisioned on-demand based on real-time policy evaluation. No persistent network tunnels exist; each session is individually authorized and encrypted.

## Workflow

### Phase 1: SDP Controller Deployment

1. **Deploy SDP Controller**
   - Install SDP controller on hardened, redundant infrastructure
   - Configure PKI integration for certificate issuance
   - Set up authentication backend (LDAP, SAML, OIDC)
   - Configure policy database with application definitions
   - Enable audit logging for all controller decisions

2. **Configure Authentication**
   - Integrate with enterprise IdP via SAML 2.0 or OIDC
   - Configure device certificate enrollment (SCEP/EST)
   - Enable multi-factor authentication requirements
   - Set up certificate revocation checking (OCSP/CRL)

3. **Define Access Policies**
   - Map users/groups to authorized applications
   - Define device posture requirements per application
   - Configure contextual conditions (location, time, risk level)
   - Set session duration and re-authentication intervals

### Phase 2: SDP Gateway Deployment

4. **Deploy Accepting Hosts (Gateways)**
   - Install SDP gateway instances in front of protected applications
   - Configure default-drop firewall rules (deny all inbound)
   - Enable SPA listener on designated ports
   - Configure mTLS with controller-issued certificates
   - Set up health monitoring and failover

5. **Configure Application Definitions**
   - Register each protected application with controller
   - Define backend server IPs, ports, and protocols
   - Configure load balancing for multi-instance applications
   - Set up application health checks

### Phase 3: Client Deployment

6. **Deploy Initiating Hosts (Clients)**
   - Install SDP client software on user endpoints
   - Enroll device certificates through automated provisioning
   - Configure SPA key material distribution
   - Test authentication flow: SPA → mTLS → application access

7. **Validate End-to-End Flow**
   - Verify SPA packets are accepted by gateway
   - Confirm mTLS handshake succeeds with valid certificates
   - Test application access through SDP tunnel
   - Verify unauthorized access is blocked (no SPA = invisible gateway)

### Phase 4: Operational Validation

8. **Security Testing**
   - Port scan SDP gateway to confirm invisibility (all ports show filtered/closed)
   - Attempt connection without valid SPA (must fail silently)
   - Test with revoked client certificate (must be denied)
   - Attempt lateral movement from one authorized app to another unauthorized app
   - Validate audit trail completeness

9. **Monitoring and Maintenance**
   - Configure SIEM integration for SDP controller and gateway logs
   - Set up alerting for failed SPA attempts and certificate errors
   - Establish certificate rotation schedule
   - Document incident response procedures for SDP events

## Validation Checklist

- [ ] SDP Controller deployed with HA and audit logging
- [ ] IdP integration tested with SAML/OIDC and MFA
- [ ] SDP Gateways deployed with default-drop firewall
- [ ] SPA mechanism validated (gateway invisible to port scans)
- [ ] mTLS established between clients and gateways
- [ ] Access policies enforce least-privilege per user/app
- [ ] Device certificate enrollment automated
- [ ] Unauthorized access attempts blocked silently
- [ ] Lateral movement between apps prevented
- [ ] Logs streaming to SIEM with alerting configured
- [ ] Certificate rotation and revocation procedures tested

## References

- CSA Software-Defined Perimeter Architecture Guide v3
- CSA SDP Specification v2.0
- NIST SP 800-207: Zero Trust Architecture
- CISA Zero Trust Maturity Model v2.0
- fwknop: Single Packet Authorization implementation

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-software-defined-perimeter
