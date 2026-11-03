---
name: conducting-api-security-testing
description: Conducts security testing of REST, GraphQL, and gRPC APIs to identify vulnerabilities in authentication, authorization, rate limiting, input validation, and business logic.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1190
- T1213
- T1552.001
- T1078
- T1071.001
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: conducting-api-security-testing@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: APIs without written authorization, for load testing or denial-of-service testing unless explicitly scoped, or for testing production APIs that process real financial transactions without safeguards.

## Prerequisites

- API documentation (OpenAPI/Swagger, GraphQL schema, Postman collection) or application access to reverse-engineer API
- Burp Suite Professional configured to intercept API traffic with JSON/XML content type handling
- Postman or Insomnia for organizing and replaying API requests across different authentication contexts
- Valid API tokens or credentials at multiple privilege levels (unauthenticated, standard user, admin)
- Target API base URL and version information

## Workflow

### Step 1: API Discovery and Documentation

Map complete API attack surface:

- **Import API documentation**: Load OpenAPI/Swagger specs into Postman or Burp Suite to catalog all endpoints, methods, parameters, and authentication requirements
- **Reverse-engineer undocumented APIs**: Proxy mobile app or web frontend through Burp Suite and exercise all features to capture API calls. Export Burp sitemap as baseline endpoint inventory.
- **GraphQL introspection**: Send introspection query to discover full schema:
  ```json
  {"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}"}
  ```
- **Endpoint enumeration**: Fuzz for hidden API versions (`/api/v1/`, `/api/v2/`, `/api/internal/`), debug endpoints (`/api/debug`, `/api/health`, `/api/metrics`), and administrative endpoints
- **Document authentication mechanisms**: Identify if API uses API keys, OAuth 2.0 Bearer tokens, JWT, session cookies, or mutual TLS

### Step 2: Authentication and Token Testing

Test authentication mechanisms for weaknesses:

- **JWT analysis**: Decode JWT and inspect claims (sub, exp, iss, aud, role). Test:
  - Algorithm confusion: Change `alg` to `none` and remove signature
  - Key confusion: Change `alg` from RS256 to HS256 and sign with public key
  - Weak secret: Brute-force HMAC secret with `hashcat -m 16500 jwt.txt wordlist.txt`
  - Token expiration: Verify tokens expire and cannot be used after expiration
  - Claim tampering: Modify role, userId, or permission claims and re-sign
- **OAuth 2.0 testing**: Check for redirect_uri manipulation, authorization code reuse, token leakage in Referer headers, and missing state parameter (CSRF)
- **API key security**: Test if API keys are validated per-endpoint, if revoked keys are immediately rejected, and if keys in query strings appear in access logs or analytics

### Step 3: Authorization Testing (BOLA/BFLA)

Test for Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA):

- **BOLA (IDOR) testing**: For every endpoint that returns user-specific data, replace object identifier with another user's identifier:
  - `GET /api/users/123/orders` -> `GET /api/users/456/orders`
  - Test with numeric IDs, UUIDs, usernames, and email addresses
  - Automate with Burp Autorize extension: configure it with two sessions (attacker and victim) and replay all requests
- **BFLA testing**: Using low-privilege token, attempt to access administrative endpoints:
  - `DELETE /api/users/456` (admin-only delete)
  - `PUT /api/users/456/role` (role modification)
  - `GET /api/admin/dashboard` (admin panel data)
- **Mass assignment**: Send additional JSON properties not shown in documentation:
  ```json
  PUT /api/users/123
  {"name": "Test", "role": "admin", "isVerified": true, "balance": 99999}
  ```
- **HTTP method testing**: If GET works on endpoint, try PUT, PATCH, DELETE, and OPTIONS to discover unprotected methods

### Step 4: Input Validation and Injection Testing

Test API inputs for injection and validation flaws:

- **SQL injection in API parameters**: Test all parameters (path, query, body, headers) with SQL injection payloads. JSON APIs are often overlooked: `{"username": "admin' OR 1=1--", "password": "test"}`
- **NoSQL injection**: For MongoDB backends, test with operator injection: `{"username": {"$gt": ""}, "password": {"$gt": ""}}`
- **SSRF via API**: Test any parameter that accepts URLs (webhook URLs, avatar URLs, import endpoints) with internal addresses and cloud metadata endpoints
- **GraphQL-specific injection**: Test for query depth attacks, alias-based batching for brute force, and field suggestion enumeration
- **XXE in XML APIs**: Submit XML content with external entity declarations to API endpoints that accept XML
- **Rate limiting validation**: Send 100+ rapid requests to authentication endpoints, password reset, and OTP verification to test for brute force protection

### Step 5: Data Exposure and Response Analysis

Check for excessive data exposure in API responses:

- **Verbose responses**: Compare data returned in API responses with what UI displays. APIs often return more fields than needed (internal IDs, creation timestamps, email addresses of other users, role information).
- **Error message analysis**: Trigger errors by sending malformed input, invalid tokens, and non-existent resources. Check if error messages reveal stack traces, database queries, internal paths, or technology details.
- **Pagination and enumeration**: Test if enumeration is possible by iterating through paginated responses (`/api/users?page=1`, `page=2`, etc.) to extract all records
- **GraphQL data exposure**: Query for fields not intended for current user's role. Test nested queries that traverse relationships to access unauthorized data.
- **Debug endpoints**: Check `/api/debug`, `/api/status`, `/metrics`, `/health`, `/.env`, `/api/swagger.json` for exposed internal information

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization (OWASP API #1); failure to verify that requesting user is authorized to access specific object, enabling IDOR attacks |
| **BFLA** | Broken Function Level Authorization (OWASP API #5); failure to restrict administrative or privileged API functions from being accessed by lower-privilege users |
| **Mass Assignment** | Vulnerability where API binds client-provided data to internal object properties without filtering, allowing attackers to modify fields they should not have access to |
| **GraphQL Introspection** | Built-in GraphQL feature that exposes complete API schema including all types, fields, and relationships; should be disabled in production |
| **JWT** | JSON Web Token; self-contained token format used for API authentication containing claims signed with secret or key pair |
| **Rate Limiting** | Controls that restrict number of API requests client can make within time window, preventing brute force, enumeration, and abuse |

## Tools & Systems

- **Burp Suite Professional**: HTTP proxy for intercepting, modifying, and replaying API requests with extensions like Autorize for automated authorization testing
- **Postman**: API development platform used for organizing endpoint collections, scripting tests, and comparing responses across authentication contexts
- **GraphQL Voyager**: Visual tool for exploring GraphQL schemas obtained through introspection queries
- **jwt.io / jwt_tool**: Tools for decoding, analyzing, and tampering with JWT tokens to test authentication bypasses
- **Nuclei**: Template-based scanner with API-specific templates for detecting common misconfigurations and known vulnerabilities

### Scenario: API Security Assessment for Fintech Mobile Application

**Context**: Fintech startup has mobile banking application with REST API backend. API handles account management, fund transfers, bill payments, and transaction history. Tester has Swagger documentation and accounts at user and admin levels.

**Approach**:
1. Import Swagger spec into Postman, generating 87 endpoint collections across 12 controllers
2. Discover BOLA on `/api/v1/accounts/{accountId}/transactions` allowing any authenticated user to view any account's transaction history
3. Find mass assignment on user update endpoint where adding `"dailyTransferLimit": 999999` bypasses configured transfer limit
4. Identify that fund transfer endpoint lacks rate limiting, allowing unlimited transfer attempts without throttling
5. Discover that JWT tokens have a 30-day expiration with no refresh token rotation, enabling long-lived session hijacking
6. Find that admin endpoint `/api/v1/admin/users` is accessible with standard user token (BFLA)
7. Report all findings with CVSS scores and specific API code-level remediation guidance

**Pitfalls**:
- Testing only endpoints documented in Swagger and missing undocumented or deprecated API versions
- Not testing same endpoint with tokens from every privilege level to detect authorization bypasses
- Ignoring response body analysis for excessive data exposure when UI only shows subset of returned fields
- Failing to test for mass assignment by only sending fields shown in documentation

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-api-security-testing
