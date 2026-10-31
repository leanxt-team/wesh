---
name: implementing-cloud-waf-rules
description: Deploys and tunes Web Application Firewall rules on AWS WAF, Azure WAF, and Cloudflare, covering managed rule sets, custom business-logic rules, rate limiting, bot management, and false-positive reduction.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T0816
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: implementing-cloud-waf-rules@54a7988 Apache-2.0, modified by wesh
---
Not for: network-level DDoS protection (use AWS Shield or Azure DDoS Protection), for API authentication design (see managing-cloud-identity-with-okta), or for application code-level security fixes (WAF is a compensating control, not a replacement for secure code).

## Prerequisites

- AWS ALB/CloudFront, Azure Application Gateway, or Cloudflare configured as application entry point
- Application traffic logs for baseline analysis before WAF deployment
- Test environment for validating WAF rules before production enforcement
- Understanding of application request patterns to minimize false positives

## Workflow

### Step 1: Deploy Managed Rule Sets

Enable cloud provider managed rule sets that cover OWASP Top 10 vulnerabilities. Start in Count (detection) mode before switching to Block (prevention) mode.

```bash
# AWS WAF: Create Web ACL with AWS Managed Rules
aws wafv2 create-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --default-action '{"Allow": {}}' \
  --visibility-config '{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "production-waf"
  }' \
  --rules '[
    {
      "Name": "AWSManagedRulesCommonRuleSet",
      "Priority": 1,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesSQLiRuleSet",
      "Priority": 2,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SQLiRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesKnownBadInputsRuleSet",
      "Priority": 3,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "KnownBadInputs"
      }
    }
  ]'
```

### Step 2: Create Custom Rate Limiting Rules

Deploy rate-based rules to protect login endpoints against brute force and credential stuffing attacks.

```bash
# Rate limiting rule for login endpoint (100 requests per 5 minutes per IP)
aws wafv2 update-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action '{"Allow": {}}' \
  --rules '[
    {
      "Name": "RateLimitLogin",
      "Priority": 0,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 100,
          "AggregateKeyType": "IP",
          "ScopeDownStatement": {
            "ByteMatchStatement": {
              "FieldToMatch": {"UriPath": {}},
              "PositionalConstraint": "STARTS_WITH",
              "SearchString": "/api/auth/login",
              "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
            }
          }
        }
      },
      "Action": {"Block": {"CustomResponse": {"ResponseCode": 429}}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitLogin"
      }
    }
  ]'
```

### Step 3: Configure Geo-Blocking and IP Reputation

Block traffic from countries where application has no legitimate users and leverage IP reputation lists to block known malicious sources.

```bash
# AWS WAF: Geo-blocking rule
# Block countries not in the allowed list
aws wafv2 create-ip-set \
  --name blocked-ips \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "198.51.100.0/24" "203.0.113.0/24"
# Add Amazon IP Reputation rule
# AWSManagedRulesAmazonIpReputationList blocks IPs flagged by AWS threat intelligence
```

### Step 4: Tune Rules to Reduce False Positives

Analyze WAF logs in Count mode to identify legitimate requests being flagged. Create rule exceptions for specific URI paths or request patterns.

```bash
# Enable WAF logging to S3
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/production-waf/id",
    "LogDestinationConfigs": ["arn:aws:s3:::waf-logs-bucket"],
    "RedactedFields": [{"SingleHeader": {"Name": "authorization"}}]
  }'
# Query WAF logs with Athena to find false positives
# Find rules triggered most frequently for legitimate traffic
cat << 'EOF' > waf-analysis.sql
SELECT
  terminatingRuleId,
  httpRequest.uri,
  httpRequest.httpMethod,
  COUNT(*) as block_count
FROM waf_logs
WHERE action = 'BLOCK'
  AND timestamp > date_add('day', -7, now())
GROUP BY terminatingRuleId, httpRequest.uri, httpRequest.httpMethod
ORDER BY block_count DESC
LIMIT 20
EOF
```

```bash
# Exclude specific rule from managed rule set that causes false positives
# Example: Exclude SizeRestrictions_BODY for file upload endpoint
aws wafv2 update-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --rules '[{
    "Name": "AWSManagedRulesCommonRuleSet",
    "Priority": 1,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesCommonRuleSet",
        "ExcludedRules": [{"Name": "SizeRestrictions_BODY"}]
      }
    },
    "OverrideAction": {"None": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "CommonRuleSet"
    }
  }]'
```

### Step 5: Switch to Block Mode After Validation

After 7-14 days of Count mode with acceptable false positive rates, switch managed rules to Block mode for active protection.

```bash
# Change OverrideAction from Count to None (use rule group's default Block action)
# Update each managed rule group from {"Count": {}} to {"None": {}}
# Monitor CloudWatch metrics for sudden changes in blocked request volume
```

## Key Concepts

| Term | Definition |
|------|------------|
| Web ACL | Web Access Control List defining set of rules evaluated against every HTTP request to protected resource |
| Managed Rule Group | Pre-configured rule set maintained by cloud provider or third-party vendor covering common attack patterns |
| Rate-Based Rule | WAF rule that tracks request rates per IP address and blocks IPs exceeding threshold within time window |
| Count Mode | WAF action that logs matching requests without blocking them, used for rule validation before enforcement |
| Rule Priority | Numerical ordering determining which rules are evaluated first; lower numbers have higher priority |
| Custom Response | WAF capability to return specific HTTP status codes and headers when blocking requests |
| Scope-Down Statement | Condition that narrows rate-based rule to specific URI paths, methods, or headers |
| False Positive | Legitimate request incorrectly blocked by WAF rule, requiring rule tuning or exclusion |

## Tools & Systems

- **AWS WAF**: Cloud-native WAF integrated with ALB, CloudFront, API Gateway, and AppSync
- **Azure WAF**: Web application firewall on Application Gateway or Front Door with OWASP CRS rule sets
- **AWS Firewall Manager**: Centralized WAF policy management across multiple AWS accounts in Organization
- **WAF Security Automations**: AWS solution that deploys Lambda-based automated WAF rule updates based on log analysis
- **CloudWatch Metrics**: Monitoring dashboard for tracking WAF rule match rates, block counts, and allowed requests

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-cloud-waf-rules
