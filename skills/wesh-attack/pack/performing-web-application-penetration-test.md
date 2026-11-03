---
name: performing-web-application-penetration-test
description: Performs systematic security testing of web applications following the OWASP Web Security Testing Guide (WSTG) methodology to identify vulnerabilities in authentication, authorization, input validation, session management, and business logic.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: performing-web-application-penetration-test@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: web applications without written authorization, against production systems during peak traffic hours without explicit approval, or for denial-of-service testing of web infrastructure.

## Prerequisites

- Signed statement of work (SoW) defining target application URLs, environments (staging/production), and testing boundaries
- Burp Suite Professional license with up-to-date extensions (Active Scan++, Autorize, JSON Beautifier, Logger++)
- Valid test accounts at each privilege level (unauthenticated, standard user, administrator) for authorization testing
- Application documentation including API specifications (OpenAPI/Swagger), sitemap, and technology stack details
- Browser configured with Burp Suite proxy (FoxyProxy recommended) and Burp CA certificate installed

## Workflow

### Step 1: Reconnaissance and Application Mapping

Map entire attack surface of web application:

- Configure Burp Suite proxy and spider application by browsing every page, form, and function manually while Burp captures sitemap
- Use Burp's Discover Content feature to find hidden directories and files not linked from visible application
- Identify technology stack from response headers (`X-Powered-By`, `Server`), cookies (JSESSIONID = Java, PHPSESSID = PHP, ASP.NET_SessionId = .NET), and page extensions
- Enumerate endpoints using `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://target.com/FUZZ -mc 200,301,302,403`
- Review JavaScript files for hardcoded API endpoints, secrets, and client-side routing using Burp's JS Link Finder extension or `LinkFinder.py`
- Document all entry points: URL parameters, POST bodies, HTTP headers, cookies, file uploads, and WebSocket connections

### Step 2: Authentication Testing

Test authentication mechanisms for weaknesses:

- **Credential enumeration**: Submit valid and invalid usernames to identify differences in response (timing, message, HTTP status) that reveal valid accounts
- **Brute force protection**: Attempt 10-20 rapid login attempts with invalid credentials to verify account lockout and rate limiting are enforced
- **Password policy**: Test password creation with weak passwords (123456, password, single character) to verify policy enforcement
- **Multi-factor authentication bypass**: Test for MFA bypass by directly accessing post-authentication pages, manipulating MFA tokens, or replaying successful MFA responses
- **Session fixation**: Note session token before and after authentication. If token does not change after login, session fixation is possible
- **Remember me functionality**: Inspect persistent authentication tokens for predictability, encryption, and proper expiration
- **Password reset**: Test password reset flow for token predictability, token expiration, account enumeration via reset form, and host header injection

### Step 3: Authorization Testing

Verify that access controls are properly enforced:

- **Horizontal privilege escalation (IDOR)**: Using Account A, capture requests that access Account A's resources. Replay those requests substituting Account B's identifiers (user IDs, order numbers, filenames). Use Burp's Autorize extension to automate this across all endpoints.
- **Vertical privilege escalation**: Using low-privilege account, attempt to access administrative functions by directly browsing to admin URLs, modifying role parameters in requests, or manipulating JWT claims
- **Forced browsing**: Attempt to access resources that should require authentication by directly navigating to internal URLs collected during mapping
- **HTTP method tampering**: If GET is blocked on endpoint, try PUT, POST, DELETE, PATCH, or use method override headers (`X-HTTP-Method-Override: DELETE`)
- **Path traversal in authorization**: Test URL path manipulation (`/api/users/123/../456/profile`) to bypass path-based authorization checks

### Step 4: Input Validation and Injection Testing

Test all input points for injection vulnerabilities:

- **SQL injection**: Insert payloads like `' OR 1=1--`, `' UNION SELECT NULL,NULL--`, and time-based blind payloads (`'; WAITFOR DELAY '0:0:5'--`) into every parameter. Use sqlmap for automated detection and exploitation of confirmed injection points.
- **Cross-Site Scripting (XSS)**: Test reflected, stored, and DOM-based XSS with payloads like `<script>alert(document.domain)</script>`, `"><img src=x onerror=alert(1)>`, and event handlers. Test in all contexts: HTML body, attributes, JavaScript, and URLs.
- **Server-Side Request Forgery (SSRF)**: Supply internal URLs (`http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1:6379/`) in parameters that fetch external resources (webhooks, image URLs, import functions)
- **Command injection**: Insert OS command separators (`;`, `|`, `&&`, `` ` ``) followed by commands (`id`, `whoami`, `ping -c 3 collaborator.net`) in parameters processed by server
- **XML External Entity (XXE)**: Submit XML payloads with external entity declarations (`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`) in XML upload or API endpoints
- **Server-Side Template Injection (SSTI)**: Test with `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` in parameters rendered by template engines

### Step 5: Session Management Testing

Evaluate security of session handling:

- **Session token analysis**: Collect 100+ session tokens and analyze for randomness using Burp Sequencer. Check token length (minimum 128 bits of entropy), character set, and predictability.
- **Session expiration**: Verify that sessions expire after defined idle timeout and absolute timeout. Test by capturing session token, waiting beyond timeout, and replaying.
- **Cookie security flags**: Verify `Secure`, `HttpOnly`, and `SameSite` flags are set on session cookies. Missing `HttpOnly` enables XSS-based session theft. Missing `SameSite` enables CSRF.
- **CSRF testing**: Identify state-changing operations (password change, email update, fund transfer) and test if they can be triggered from cross-origin page without valid CSRF token
- **Concurrent session handling**: Test if application limits number of concurrent sessions and if logging in from new location invalidates previous session

### Step 6: Business Logic Testing

Test application-specific logic flaws that automated scanners cannot detect:

- **Race conditions**: Send multiple simultaneous requests to exploit time-of-check-to-time-of-use (TOCTOU) vulnerabilities (double-spending, coupon reuse, voting multiple times) using Burp Turbo Intruder
- **Workflow bypass**: Attempt to skip steps in multi-step processes (checkout, registration, approval) by directly requesting later-stage endpoints
- **Numeric manipulation**: Modify prices, quantities, or amounts to negative values, zero, or extremely large numbers to test for integer overflow or logic errors
- **File upload bypass**: Test file upload restrictions by modifying MIME types, double extensions (file.php.jpg), null bytes (file.php%00.jpg), and content-type manipulation

### Step 7: Report and Remediation Guidance

Compile all findings into structured report:

- Write executive summary describing overall application security posture in business terms
- Document each finding with title, severity (CVSS 3.1), affected URL/parameter, description, reproduction steps, screenshots, and HTTP request/response pairs from Burp
- Provide specific remediation guidance for each finding including code-level fixes where applicable
- Include risk matrix showing distribution of findings by severity
- Deliver report securely (encrypted, not via email attachment) and schedule findings walkthrough with development team

## Key Concepts

| Term | Definition |
|------|------------|
| **OWASP WSTG** | Web Security Testing Guide; comprehensive open-source guide to testing web application security organized by test category (authentication, authorization, input validation, etc.) |
| **IDOR** | Insecure Direct Object Reference; vulnerability where application exposes internal object identifiers and fails to verify requesting user is authorized to access that object |
| **CSRF** | Cross-Site Request Forgery; attack that forces authenticated user's browser to send forged request to vulnerable web application |
| **Session Fixation** | Attack where attacker sets user's session ID to known value before user authenticates, then hijacks session after login |
| **Forced Browsing** | Attempting to access application resources by directly requesting URLs not linked from visible application, bypassing intended access controls |
| **SSTI** | Server-Side Template Injection; injecting template directives into server-side template engines to achieve remote code execution |

## Tools & Systems

- **Burp Suite Professional**: Primary web application testing proxy providing interception, scanning, and manual testing tools including Repeater, Intruder, and Sequencer
- **ffuf**: Fast web fuzzer for directory/file discovery, parameter fuzzing, and virtual host enumeration
- **sqlmap**: Automated SQL injection detection and exploitation tool supporting all major database engines and injection techniques
- **Nuclei**: Template-based vulnerability scanner with community-maintained templates for known CVEs and misconfigurations
- **SecLists**: Curated collection of wordlists for fuzzing, credential testing, and payload delivery used throughout web application testing

### Scenario: E-Commerce Application Pre-Launch Security Assessment

**Context**: Retail company is launching new e-commerce platform built on Node.js with React frontend and PostgreSQL database. Application handles credit card payments through Stripe integration and stores customer PII. Testing scope includes staging environment with full API access.

**Approach**:
1. Map application through manual browsing and API documentation review, identifying 47 unique endpoints
2. Test authentication flows including social login (OAuth), standard login, and password reset
3. Discover IDOR vulnerability in order retrieval API (`/api/orders/{orderId}`) where any authenticated user can view any order by iterating order IDs
4. Identify stored XSS in product review feature that executes when administrators view admin dashboard
5. Find SSRF in product image import function that allows reading AWS EC2 instance metadata
6. Test payment logic by manipulating price values in client-side cart before checkout submission
7. Report all findings with specific Node.js code-level remediation (parameterized queries, input sanitization with DOMPurify, authorization middleware)

**Pitfalls**:
- Testing only frontend while ignoring API layer that lacks independent authorization checks
- Missing business logic flaws by relying solely on automated scanning without manual testing
- Not testing same functionality across different privilege levels to catch authorization issues
- Overlooking client-side JavaScript for hardcoded API keys, debug endpoints, and internal URLs

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-web-application-penetration-test
