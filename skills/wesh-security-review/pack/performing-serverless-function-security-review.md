---
name: performing-serverless-function-security-review
description: Performing security reviews of serverless functions across AWS Lambda, Azure Functions, and GCP Cloud Functions to identify overly permissive execution roles, insecure environment variables, injection vulnerabilities, and missing runtime protections.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1055
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: performing-serverless-function-security-review@54a7988 Apache-2.0, modified by wesh
---
Not for: container or VM security assessments (use container scanning tools), for API security testing (use DAST tools on the API Gateway layer), or for real-time serverless threat detection (use AWS Lambda Extensions with security agents).

## Prerequisites

- AWS CLI, Azure CLI, and gcloud CLI configured with appropriate permissions
- Access to read function configurations, policies, and execution roles
- Prowler or Checkov for automated serverless security scanning
- SAM CLI or Serverless Framework for local function analysis
- CloudTrail, Azure Monitor, or Cloud Audit Logs enabled for function invocation monitoring

## Workflow

### Step 1: Enumerate All Serverless Functions and Configurations

List all functions across cloud providers with their runtime, memory, timeout, and network settings.

```bash
# AWS Lambda: List all functions with key security attributes
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Runtime,MemorySize,Timeout,Role,VpcConfig.VpcId,Layers[*].Arn]' \
  --output table
# Check for functions using deprecated runtimes
aws lambda list-functions \
  --query 'Functions[?Runtime==`python3.7` || Runtime==`nodejs14.x` || Runtime==`dotnetcore3.1`].[FunctionName,Runtime]' \
  --output table
# Azure Functions: List all function apps
az functionapp list \
  --query "[].{Name:name, Runtime:siteConfig.linuxFxVersion, ResourceGroup:resourceGroup, HttpsOnly:httpsOnly}" \
  -o table
# GCP Cloud Functions: List all functions
gcloud functions list \
  --format="table(name, runtime, status, httpsTrigger.url, serviceAccountEmail, vpcConnector)"
```

### Step 2: Audit Execution Role Permissions

Review IAM roles attached to functions for overly permissive policies.

```bash
# AWS: Check each Lambda function's execution role
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  role_arn=$(aws lambda get-function-configuration --function-name "$func" --query 'Role' --output text)
  role_name=$(echo "$role_arn" | awk -F'/' '{print $NF}')
  echo "=== $func -> $role_name ==="
  # List attached policies
  aws iam list-attached-role-policies --role-name "$role_name" \
    --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output table
  # Check for wildcard actions
  for policy_arn in $(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyArn' --output text); do
    version=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
    aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version" \
      --query 'PolicyVersion.Document' --output json | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for stmt in doc.get('Statement', []):
    actions = stmt.get('Action', [])
    if isinstance(actions, str): actions = [actions]
    resources = stmt.get('Resource', [])
    if isinstance(resources, str): resources = [resources]
    if '*' in actions or any(a.endswith(':*') for a in actions):
        print(f'  WARNING: {stmt[\"Effect\"]} {actions} on {resources}')
" 2>/dev/null
  done
done
```

### Step 3: Check Environment Variables for Secrets

Scan function environment variables for hardcoded credentials, API keys, and database connection strings.

```bash
# AWS Lambda: Extract environment variables
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  envvars=$(aws lambda get-function-configuration --function-name "$func" \
    --query 'Environment.Variables' --output json 2>/dev/null)
  if [ "$envvars" != "null" ] && [ -n "$envvars" ]; then
    echo "=== $func ==="
    echo "$envvars" | python3 -c "
import json, sys, re
vars = json.load(sys.stdin)
sensitive_patterns = [
    r'(?i)(password|secret|key|token|credential|api.?key)',
    r'(?i)(aws.?access|aws.?secret)',
    r'(?i)(database.?url|connection.?string|db.?pass)',
    r'AKIA[0-9A-Z]{16}'
]
for key, value in vars.items():
    for pattern in sensitive_patterns:
        if re.search(pattern, key) or re.search(pattern, str(value)):
            masked = value[:4] + '****' + value[-4:] if len(value) > 8 else '****'
            print(f'  SENSITIVE: {key} = {masked}')
            break
"
  fi
done
# Azure Functions: Check app settings
for app in $(az functionapp list --query "[].name" -o tsv); do
  rg=$(az functionapp show --name "$app" --query "resourceGroup" -o tsv)
  echo "=== $app ==="
  az functionapp config appsettings list \
    --name "$app" --resource-group "$rg" \
    --query "[?contains(name,'KEY') || contains(name,'SECRET') || contains(name,'PASSWORD')].{Name:name}" \
    -o table 2>/dev/null
done
```

### Step 4: Review Function Triggers and Access Controls

Verify that function triggers have appropriate authentication and authorization.

```bash
# AWS: Check for unauthenticated Lambda function URLs
aws lambda list-function-url-configs \
  --function-name FUNCTION_NAME \
  --query 'FunctionUrlConfigs[*].[FunctionUrl,AuthType,Cors]' --output table
# Check for resource-based policies allowing public invocation
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  policy=$(aws lambda get-policy --function-name "$func" --query 'Policy' --output text 2>/dev/null)
  if [ -n "$policy" ]; then
    echo "$policy" | python3 -c "
import json, sys
doc = json.loads(sys.stdin.read())
for stmt in doc.get('Statement', []):
    principal = stmt.get('Principal', {})
    if principal == '*' or principal == {'AWS': '*'}:
        print(f'WARNING: $func has public invoke policy: {stmt.get(\"Sid\", \"unnamed\")}')" 2>/dev/null
  fi
done
# GCP: Check for unauthenticated Cloud Functions
gcloud functions list --format=json | python3 -c "
import json, sys
functions = json.load(sys.stdin)
for func in functions:
    name = func.get('name', '').split('/')[-1]
    trigger = func.get('httpsTrigger', {})
    if trigger and func.get('ingressSettings') == 'ALLOW_ALL':
        print(f'WARNING: {name} allows all ingress traffic')
"
```

### Step 5: Analyze Function Code for Security Vulnerabilities

Review function code for common serverless security issues.

```bash
# Download Lambda function code for review
aws lambda get-function --function-name FUNCTION_NAME \
  --query 'Code.Location' --output text | xargs curl -o function.zip
unzip function.zip -d function-code/
# Scan with Bandit (Python) or ESLint security plugin (Node.js)
# Python functions
pip install bandit
bandit -r function-code/ -f json -o bandit-results.json
# Node.js functions
npm install -g eslint @microsoft/eslint-plugin-sdl
eslint --ext .js function-code/
# Check for common serverless vulnerabilities:
# 1. SQL injection in database queries
# 2. Command injection via os.system or subprocess
# 3. Insecure deserialization
# 4. Event data injection (untrusted event parameters)
# 5. Excessive function permissions
grep -rn "os.system\|subprocess\|eval(\|exec(" function-code/ || echo "No obvious injection patterns"
grep -rn "pickle.loads\|yaml.load\b" function-code/ || echo "No deserialization risks"
```

### Step 6: Run Automated Serverless Security Scanning

Execute Checkov and Prowler for automated compliance checks on serverless resources.

```bash
# Checkov scan for serverless frameworks
checkov -d ./serverless-project/ \
  --framework serverless \
  --output json > checkov-serverless.json
# Prowler Lambda-specific checks
prowler aws \
  --checks lambda_function_no_secrets_in_variables \
           lambda_function_url_auth_type \
           lambda_function_using_supported_runtimes \
           lambda_function_not_publicly_accessible \
  -M json-ocsf \
  -o ./prowler-lambda/
```

## Key Concepts

| Term | Definition |
|------|------------|
| Execution Role | IAM role assumed by serverless function during execution that defines what AWS/cloud resources function can access |
| Event Injection | Serverless-specific attack where untrusted data in event trigger payload is used unsafely in function logic |
| Function URL | Direct HTTP(S) endpoint for invoking Lambda functions without API Gateway, which may be configured without authentication |
| Cold Start | Initial function execution that includes container provisioning, during which security agents and extensions must initialize |
| Resource-Based Policy | Policy attached to function itself that defines who can invoke it, separate from execution role |
| Secrets Manager Integration | Pattern of retrieving sensitive configuration from secrets management service rather than storing in environment variables |

## Tools & Systems

- **AWS Lambda**: Primary serverless compute platform with execution roles, layers, and resource policies
- **Checkov**: Static analysis tool for infrastructure-as-code with serverless-specific security policies
- **Prowler**: Cloud security tool with Lambda-specific checks for permissions, public access, and runtime versions
- **Bandit**: Python static analysis tool for detecting security issues in function source code
- **OWASP Serverless Top 10**: Security risk framework specific to serverless architectures

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-serverless-function-security-review
