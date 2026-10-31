---
name: implementing-zero-trust-network-access-with-zscaler
description: Configures Zero Trust Network Access using Zscaler Private Access (ZPA) to broker identity-based, context-aware connections between authenticated users and internal applications through the Zscaler Zero Trust Exchange, without placing users on the corporate network.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1078
- T1190
- T1059
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: implementing-zero-trust-network-access-with-zscaler@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Understanding of zero trust principles (NIST SP 800-207)
- Familiarity with identity providers (Okta, Azure AD, Ping Identity)
- Knowledge of network security fundamentals
- Access to Zscaler Private Access (ZPA) tenant

## Prerequisites

- Familiarity with zero trust architecture concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Architecture

### Zscaler Private Access Components

1. **Client Connector**: Lightweight agent on user endpoints that establishes outbound TLS tunnels to nearest ZPA Service Edge
2. **ZPA Service Edge**: Cloud-hosted broker (or Private Service Edge on-premises) that stitches user-to-app connections after policy evaluation
3. **App Connector**: Lightweight VM deployed in application environment that creates outbound tunnels to Service Edge
4. **ZPA Admin Portal**: Centralized management console for defining applications, segments, and access policies

### Connection Flow

```
User Device (Client Connector)
    |
    v [Outbound TLS tunnel]
ZPA Service Edge (Policy Evaluation + IdP Auth)
    |
    v [Outbound TLS tunnel]
App Connector --> Internal Application
```

Key principle: No inbound connections are required. Both Client Connector and App Connector initiate outbound-only connections, eliminating attack surface of traditional VPNs.

## Key Concepts

### Application Segments
Define specific applications or groups of applications by IP address, FQDN, port, and protocol. Segments enable granular microsegmentation rather than broad network access.

### Access Policies
Policies combine user identity, group membership, device posture, and contextual signals (location, time) to grant or deny access to application segments.

### Server Groups
Logical groupings of App Connectors that serve specific application segments, enabling high availability and geographic distribution.

### Browser Access
ZPA supports clientless browser-based access for web applications, enabling ZTNA for unmanaged devices and third-party users without requiring Client Connector.

## Workflow

### Phase 1: Foundation Setup

1. **Configure Identity Provider Integration**
   - Navigate to Administration > IdP Configuration in ZPA Admin Portal
   - Add SAML 2.0 or OIDC integration with your IdP (Azure AD, Okta, Ping)
   - Configure SCIM provisioning for automatic user/group synchronization
   - Test SSO authentication flow

2. **Deploy App Connectors**
   - Provision App Connector VMs in each application environment (data center, AWS VPC, Azure VNet)
   - Download provisioning key from ZPA Admin Portal
   - Install and enroll App Connector using provisioning key
   - Verify connector status shows "Healthy" in admin portal
   - Deploy at least two connectors per environment for high availability

3. **Create Server Groups**
   - Group App Connectors by geographic location or application tier
   - Configure health check intervals and failover behavior

### Phase 2: Application Segmentation

4. **Define Application Segments**
   - Create segments for each application or logical group
   - Specify domains/IPs, ports, and protocols
   - Associate segments with appropriate server groups
   - Enable or disable browser access as needed

5. **Create Segment Groups**
   - Organize application segments into logical groups (e.g., HR apps, Finance apps)
   - Use segment groups to simplify policy management

### Phase 3: Policy Configuration

6. **Configure Access Policies**
   - Define rules matching user groups to application segments
   - Apply conditions: device posture, client type, SAML attributes
   - Order rules by priority (most restrictive first)
   - Create deny rules for blocked access scenarios

7. **Enable Device Posture Checks**
   - Configure posture profiles requiring OS patch level, disk encryption, antivirus status
   - Integrate with endpoint management (CrowdStrike, Microsoft Intune, Carbon Black)
   - Associate posture profiles with access policies

### Phase 4: Client Deployment

8. **Deploy Client Connector**
   - Package Zscaler Client Connector with enrollment token
   - Deploy via MDM (Intune, Jamf, SCCM) or manual installation
   - Configure forwarding profile to route private app traffic through ZPA
   - Test user authentication and application access

### Phase 5: Monitoring and Optimization

9. **Enable Logging and Monitoring**
   - Configure log streaming to SIEM (Splunk, Sentinel, QRadar)
   - Set up alerts for policy violations, connector health, and authentication failures
   - Review ZPA Insights dashboard for usage analytics

10. **Iterative Refinement**
    - Analyze access logs to identify shadow IT and unauthorized access attempts
    - Refine application segments based on actual traffic patterns
    - Expand coverage from pilot applications to full enterprise deployment

## Validation Checklist

- [ ] Identity provider integration tested with SSO and SCIM sync
- [ ] App Connectors deployed and showing healthy status in all environments
- [ ] Application segments defined with correct IPs/FQDNs, ports, protocols
- [ ] Access policies enforce least-privilege per user group
- [ ] Device posture checks block non-compliant endpoints
- [ ] Client Connector deployed to all managed endpoints
- [ ] Log streaming to SIEM confirmed with test events
- [ ] Failover tested by disabling one App Connector per server group
- [ ] Browser Access configured for web apps requiring third-party access
- [ ] VPN decommission plan documented with rollback procedures

## References

- NIST SP 800-207: Zero Trust Architecture
- CISA Zero Trust Maturity Model v2.0 - Network Pillar
- Zscaler Private Access Architecture Guide
- CSA Software-Defined Perimeter and Zero Trust Specification v2.0

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-zero-trust-network-access-with-zscaler
