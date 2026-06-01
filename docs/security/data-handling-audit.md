# Data Handling & Audit Integrity Audit

**Date:** 2026-06-01
**Branch:** `security_assessment`
**Scope:** S3 WORM compliance, audit data immutability, CloudWatch session log completeness and tamper resistance, sensitive data exposure in logs and environment variables
**Machine-readable findings:** `adversary-findings.json` (IDs referenced where applicable)
**Files reviewed:**
- `deploy/regional/s3.tf`
- `deploy/regional/iam.tf`
- `deploy/regional/ecs.tf`
- `deploy/regional/main.tf`
- `deploy/regional/kms.tf`
- `deploy/regional/lambda-create-investigation.tf`
- `deploy/regional/lambda-reap-tasks.tf`
- `deploy/regional/lambda-invoker.tf`
- `deploy/regional/efs.tf`
- `deploy/regional/oidc.tf`
- `deploy/regional/variables.tf`
- `entrypoint.sh`
- `lambda/create-investigation/handler.py`
- `lambda/reap-tasks/handler.py`

---

## S3 Audit Bucket

### HIGH — Object Lock Not Enabled at Bucket Creation (aws_s3_bucket Missing `object_lock_enabled = true`)

**File:** `deploy/regional/s3.tf`, line 2  
**Severity:** HIGH

**Issue:**  
The `aws_s3_bucket.audit` resource does not set `object_lock_enabled = true`. In AWS, Object Lock must be enabled at bucket creation time — it cannot be added to an existing bucket. The separate `aws_s3_bucket_object_lock_configuration.audit` resource configures COMPLIANCE mode retention, but this configuration can only take effect if Object Lock was enabled when the bucket was originally created.

The Terraform code contains this exact warning in a comment (`# This will fail if the bucket already exists without object lock`), but the comment is on the `aws_s3_bucket_object_lock_configuration` resource, not the bucket itself. If an operator runs `terraform apply` on a fresh deployment, the bucket is created **without** Object Lock enabled, and then the configuration resource fails. The result is a bucket with no WORM protection that silently accepts the state as "applied."

Terraform's `aws_s3_bucket` resource requires `object_lock_enabled = true` alongside the `aws_s3_bucket_object_lock_configuration` resource for the retention policy to have any effect.

**Impact:**  
WORM protection is not actually active. SREs with the task role could delete audit objects from the bucket (they currently lack `s3:DeleteObject`, but any operator with standard IAM access could delete objects freely). Cross-account replication to an audit account that does have Object Lock enforced also fails, because the source bucket must have versioning and Object Lock enabled as prerequisites.

FedRAMP AU-9 (Protection of Audit Information) requires that audit records be protected from unauthorized modification and deletion. A non-WORM audit bucket does not satisfy this control.

**Recommendation:**  
Add `object_lock_enabled = true` directly to the `aws_s3_bucket` resource:

```hcl
resource "aws_s3_bucket" "audit" {
  bucket              = local.bucket_name
  object_lock_enabled = true   # Must be set at bucket creation
  tags                = local.common_tags
}
```

If the bucket already exists without Object Lock, it must be recreated (or Object Lock enabled via the AWS Console's one-time migration path, which is not yet available via Terraform). Add a `lifecycle { prevent_destroy = true }` block to prevent accidental destruction of the WORM bucket after it is correctly provisioned.

---

### MEDIUM — S3 Lifecycle Rule May Conflict With Object Lock Intent (Delete Markers)

**File:** `deploy/regional/s3.tf`, lines 102–119  
**Severity:** MEDIUM

**Issue:**  
The lifecycle rule at lines 102–119 includes:

```hcl
expiration {
  expired_object_delete_marker = true
}
```

This rule automatically deletes expired object delete markers. In a versioned, Object Lock-enabled bucket, delete markers are not themselves protected by COMPLIANCE retention (only actual object versions are). However, deleting expired delete markers prematurely can cause confusion in audit tools that walk version history: an auditor scanning the bucket for gaps in write activity may misinterpret absent delete markers as evidence of tampering when they were simply cleaned up by the lifecycle rule.

Additionally, if a misconfiguration allows delete markers to be created on objects that are still within their retention period (a condition that Object Lock COMPLIANCE mode should block, but which can occur due to SDK-level issues), the lifecycle rule could automatically clean up those markers before the gap is detected.

**Impact:**  
This is primarily an audit integrity and forensic clarity issue. The deletion of delete markers does not directly bypass WORM protection for retained object versions. However, for an FedRAMP system where audit trails must be complete and demonstrably untampered (AU-9, AU-10), automated cleanup of any version history metadata weakens the chain of evidence.

**Recommendation:**  
Remove the `expired_object_delete_marker` lifecycle rule from the WORM audit bucket. Object Lock buckets under FedRAMP should not have automated deletion of any version history artifacts. If storage cost management is required, use S3 Intelligent-Tiering or Glacier transition rules only (do not delete versions or markers within the retention window). Keep the `abort_incomplete_multipart_upload` rule (it does not affect completed objects or WORM-protected data).

---

### MEDIUM — Cross-Account Replication is Optional and Unverified (Weak WORM Backstop)

**File:** `deploy/regional/s3.tf`, lines 60–99  
**Severity:** MEDIUM

**Issue:**  
Cross-account replication to an audit account is configured only when `var.audit_replication_bucket_arn` is non-empty (`count = var.audit_replication_bucket_arn != "" ? 1 : 0`). The default value is `""`, meaning replication is disabled by default. There is no Terraform `check` block or `precondition` requiring replication for production deployments. The destination bucket's Object Lock configuration is documented only in a comment (lines 54–59); there is no Terraform validation that the destination bucket actually has Object Lock enabled.

The replication configuration enables `delete_marker_replication { status = "Enabled" }`, which means that if the source account is compromised and delete markers are added to objects, those markers replicate to the audit account. If the audit account's bucket also lacks WORM protection (per the HIGH finding above), delete markers in the audit copy would not be blocked either.

**Impact:**  
Without cross-account replication to a separate AWS account with distinct IAM controls, a compromise of the primary AWS account gives an attacker full control over the audit bucket. S3 Object Lock in COMPLIANCE mode cannot be bypassed by any IAM principal including root, but account-level compromise (e.g., root credentials obtained) can modify Object Lock governance. Cross-account replication to an independently controlled audit account is the standard FedRAMP backstop. Deploying without it (the default) leaves a single point of failure in the audit chain.

**Recommendation:**  
Make `audit_replication_bucket_arn` a required variable with no default for `stage=prod` deployments. Add a Terraform `check` block:

```hcl
check "prod_replication_required" {
  assert {
    condition     = var.stage != "prod" || var.audit_replication_bucket_arn != ""
    error_message = "Cross-account audit replication is required for prod deployments (FedRAMP AU-9)."
  }
}
```

Add a `precondition` on the replication resource that verifies the destination ARN format includes an account ID not equal to the current account (`data.aws_caller_identity.current.account_id`), enforcing that the destination is truly cross-account.

---

### MEDIUM — No S3 Bucket Policy Enforcing Encryption in Transit (see M6)

**File:** `deploy/regional/s3.tf`, line 1  
**Severity:** MEDIUM  
**Status:** Already captured in `adversary-findings.json` as **M6**. Not duplicated here.

---

### MEDIUM — S3 Audit Bucket Uses SSE-S3 Instead of SSE-KMS (see M4)

**File:** `deploy/regional/s3.tf`, line 48  
**Severity:** MEDIUM  
**Status:** Already captured in `adversary-findings.json` as **M4**. Not duplicated here.

---

### CONFIRMED SAFE — SRE Task Role Cannot Delete Audit Objects

The ECS task role's S3 policy (`iam.tf:124–143`) grants only:
- `s3:PutObject` — upload audit artifacts
- `s3:PutObjectAcl` — set object ACLs (flagged in M13)
- `s3:GetObject` — read objects (flagged in C1)
- `s3:ListBucket` — enumerate bucket contents (flagged in C1)

No delete permissions (`s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:DeleteBucket`, `s3:PutBucketPolicy`, `s3:PutBucketVersioning`) are granted. Combined with Object Lock COMPLIANCE mode (when correctly provisioned per the HIGH finding above), deletion is blocked both at the IAM layer and the S3 Object Lock layer.

**Note:** The HIGH finding above (missing `object_lock_enabled = true`) must be remediated for the Object Lock layer to actually provide protection.

---

## CloudWatch Session Logs

### MEDIUM — ECS Exec Session Log Encryption Disabled (see M3)

**File:** `deploy/regional/ecs.tf`, line 17  
**Severity:** MEDIUM  
**Status:** Already captured in `adversary-findings.json` as **M3**. Not duplicated here.

---

### LOW — Lambda Invocation Logs (OIDC Validation Events) Retained for Only 7 Days

**File:** `deploy/regional/variables.tf`, line 88  
**Severity:** LOW  
**Status:** Partially captured in `adversary-findings.json` as **L10** (which addresses the general case). This note adds a specific data handling angle.

The SSM session log group (`aws_cloudwatch_log_group.ssm_sessions`) uses `var.retention_days` (default 90 days), which is an appropriate retention period for FedRAMP AU-11.

However, the Lambda invocation log group (`aws_cloudwatch_log_group.create_investigation_lambda`) uses `var.log_retention_days` (default 7 days). These logs contain:
- Token validation events (OIDC issuer, subject, group membership checks)
- Investigation creation records (who, what cluster, what investigation ID, what timestamp)
- Failed authorization attempts
- ECS task ARNs created

These are security-relevant audit events under FedRAMP AU-2 and AU-3. Losing them after 7 days means an incident discovered more than a week after the fact has no Lambda-side audit evidence, even though the SSM session logs (the "what was done") are retained for 90 days. The "who authorized the session" logs are lost first.

**Recommendation:**  
Use `var.retention_days` (default 90) for the Lambda log group, consistent with the SSM sessions log group:

```hcl
resource "aws_cloudwatch_log_group" "create_investigation_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-create-investigation"
  retention_in_days = var.retention_days   # Changed from var.log_retention_days
  ...
}
```

---

### CONFIRMED SAFE — SRE Task Role Cannot Delete or Modify CloudWatch Session Logs

The ECS task role's CloudWatch Logs policy (`iam.tf:189–209`) grants only:
- `logs:CreateLogStream`
- `logs:PutLogEvents`
- `logs:DescribeLogGroups`
- `logs:DescribeLogStreams`

Critically, the following destructive actions are **not** granted:
- `logs:DeleteLogGroup`
- `logs:DeleteLogStream`
- `logs:DeleteLogEvents` (this API does not exist; log events cannot be deleted once written)

An SRE connecting via ECS Exec obtains the task role credentials. Even with those credentials, they cannot delete or modify existing CloudWatch log events. CloudWatch Logs does not provide a `DeleteLogEvents` API — once events are written, they are immutable within the log stream for the duration of the log group's retention period.

The ECS Exec session itself logs to the `ssm_sessions` log group. Since the task role can only create new streams and append events (not delete), session logs for any investigation are preserved for the full `var.retention_days` period.

---

### CONFIRMED SAFE — ECS Exec Captures Complete Bidirectional Terminal I/O

The ECS cluster configuration (`ecs.tf:7–23`) sets:

```hcl
execute_command_configuration {
  kms_key_id = aws_kms_key.exec_session.arn
  logging    = "OVERRIDE"

  log_configuration {
    cloud_watch_log_group_name     = aws_cloudwatch_log_group.ssm_sessions.name
    cloud_watch_encryption_enabled = false  # See M3
  }
}
```

The `logging = "OVERRIDE"` setting forces all ECS Exec sessions to log to the specified CloudWatch log group regardless of how the session was initiated. AWS ECS Exec captures both the input (commands typed by the SRE) and the output (command responses from the container) through the SSM session channel. This is bidirectional terminal I/O capture.

The KMS key (`aws_kms_key.exec_session.arn`) is used to encrypt the SSM channel during transit (not CloudWatch Logs — the CloudWatch encryption gap is in M3). Session logs include the full interactive terminal session content.

---

## Sensitive Data Exposure

### CONFIRMED SAFE — Lambda Handler Redacts Sensitive Headers in Logs

The Lambda handler (`handler.py:88–91`) explicitly redacts the `authorization` and `x-oidc-token` headers before logging:

```python
headers_redacted = {k: '***REDACTED***' if k.lower() in ('authorization', 'x-oidc-token') else v
                   for k, v in event.get('headers', {}).items()}
logger.info(f"Headers: {headers_redacted}")
```

The raw OIDC token is never written to CloudWatch Logs by the Lambda handler. JWT claims (sub, email, username, groups) are logged at the INFO level (e.g., `"Token validated for user: {username} (sub: {user_sub}, ...)"`), which is appropriate for audit purposes. The group names and authorization decision are also logged.

---

### CONFIRMED SAFE — Lambda Environment Variables Contain No Secrets

The Lambda environment variables (`lambda-create-investigation.tf:126–149`) include:
- `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` — OIDC configuration (not secrets; these are publicly discoverable from the OIDC discovery endpoint)
- `ECS_CLUSTER`, `TASK_DEFINITION`, `SUBNETS`, `SECURITY_GROUP`, `EFS_FILESYSTEM_ID` — infrastructure identifiers
- `SHARED_ROLE_ARN`, `S3_AUDIT_BUCKET`, `AWS_ACCOUNT_ID` — resource identifiers
- `REQUIRED_GROUPS`, `ABAC_TAG_KEY`, `TASK_TIMEOUT_DEFAULT` — configuration values

No passwords, private keys, API tokens, or credentials are passed as Lambda environment variables. The kubeconfig credentials are referenced via AWS Secrets Manager (`valueFrom` in the task definition secrets section) and injected at task launch time by ECS, not baked into Lambda environment.

---

### CONFIRMED SAFE — entrypoint.sh Does Not Log Secrets

Review of `entrypoint.sh` confirms:
- `echo "Auto-generated S3 audit path: ${S3_AUDIT_ESCROW}"` — logs S3 URI (bucket path, not credentials)
- `echo "Auto-detected AWS_REGION=${AWS_REGION} from ECS task metadata"` — logs region
- `echo "Task will be automatically stopped after ${TASK_TIMEOUT} seconds"` — logs a timeout value
- `echo "Warning: S3 audit not configured"` — warning message
- `echo "Syncing /home/sre to ${S3_AUDIT_ESCROW}..."` — operational log

None of these contain tokens, passwords, IAM credentials, or private keys. The `ECS_CONTAINER_METADATA_URI_V4` endpoint URL is used internally for metadata retrieval via `curl` but is not echoed to stdout.

AWS IAM credentials (task role) are available inside the Fargate container via the ECS credential endpoint (`$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), not as environment variables visible in task definition logs or CloudWatch. They are not explicitly echoed by entrypoint.sh.

---

### LOW — entrypoint.sh s3 sync Without --no-follow-symlinks (see M29)

**File:** `entrypoint.sh`, line 28  
**Severity:** MEDIUM  
**Status:** Already captured in `adversary-findings.json` as **M29**. This is highlighted here as a data handling finding because symlink traversal during s3 sync can cause `/proc/1/environ` (containing runtime environment variables) to be uploaded to the S3 audit bucket, which a rogue SRE can then read back via the C1 task role read permission.

---

### MEDIUM — Task Definition Environment Variables Persist After Task Stops (Residual Data)

**File:** `lambda/create-investigation/handler.py`, lines 498–519  
**Severity:** LOW

**Issue:**  
The Lambda registers per-investigation task definitions that bake `CLUSTER_ID`, `INVESTIGATION_ID`, `OC_VERSION`, `S3_AUDIT_BUCKET`, and `TASK_TIMEOUT` into the `environment` block of the container definition. These task definitions persist in the ECS task definition registry even after the task stops and the investigation is closed.

The task definition family name format is `{base_family}-{cluster_id}-{investigation_id}-{timestamp}` (handler.py:479). Any SRE with `ecs:DescribeTaskDefinition` (granted by the `DescribeAndListECS` statement in oidc.tf) can retrieve the full environment variable set for any registered task definition, including closed investigations. The kube-proxy sidecar's `secrets` section also contains the Secrets Manager ARN for the cluster kubeconfig (handler.py:507–510).

**Impact:**  
Historical investigation metadata (which SRE worked on which cluster, when, with what timeout, and the Secrets Manager ARN path for the kubeconfig) is permanently retrievable from the ECS task definition registry by any authenticated SRE. This is a data retention and information disclosure issue, particularly since investigation IDs and cluster IDs can be sensitive operational information.

Additionally, the `close-investigation` flow calls `ecs:DeregisterTaskDefinition` to clean up per-investigation task definitions. However, deregistered task definitions remain queryable via `ecs:DescribeTaskDefinition` with the INACTIVE status — deregistration does not purge the stored definition, it only prevents new tasks from being launched from it.

**Recommendation:**  
1. After `close-investigation` deregisters the task definition, use `ecs:DeleteTaskDefinitions` (available since 2023) to permanently delete the inactive definition. This requires adding `ecs:DeleteTaskDefinitions` to the Lambda IAM policy.
2. For the `DescribeTaskDefinition` exposure, see M25 in `adversary-findings.json` for the recommendation to remove or scope `ecs:DescribeTaskDefinition` from the shared SRE role.

---

## Reaper Lambda Logging

### CONFIRMED SAFE — Reaper Lambda Does Not Log Sensitive Data

The reaper Lambda (`lambda/reap-tasks/handler.py`) logs:
- Task IDs and task ARNs (operational identifiers)
- Deadline timestamps from ECS tags
- `owner_username` and `oidc_sub` tag values when stopping a task

The `oidc_sub` (OIDC subject UUID) is logged at the INFO level when a task is stopped: `f"Stopped task {task_id} (owner: {owner_username} / {oidc_sub})"`. This is appropriate audit logging — the immutable user identity associated with a task that was terminated by the reaper should be recorded. It does not constitute sensitive data exposure.

No IAM credentials, OIDC tokens, or other bearer credentials are logged or processed by the reaper Lambda.

---

## Non-Findings

The following items were examined and confirmed not to be vulnerabilities within the scope of this audit:

| Item | Result |
|---|---|
| SRE task role has s3:DeleteObject | Not granted — task role cannot delete audit objects |
| SRE task role has logs:DeleteLogStream or logs:DeleteLogEvents | Not granted — session logs cannot be tampered with via task role |
| Lambda environment variables contain secrets | No secrets in Lambda env vars; kubeconfig injected via Secrets Manager valueFrom |
| entrypoint.sh echoes tokens or credentials to stdout | Not present; AWS credentials are not echoed |
| ECS Exec session logs are one-directional (input only) | ECS Exec captures bidirectional I/O through the SSM channel |
| Lambda logs raw OIDC token values | Redacted in all log calls (lines 88–91 of handler.py) |
| Reaper Lambda logs sensitive user data inappropriately | OIDC sub and username from ECS task tags are appropriately logged at task stop events |
| S3 Object Lock retention period is configurable to 0 | var.retention_days has validation requiring valid CloudWatch periods (minimum 1 day); defaults to 90 |
| SREs can call s3:PutBucketPolicy to grant themselves delete | Not in task role IAM policy |
| SREs can call s3:DeleteObjectVersion | Not in task role IAM policy |
| MFA delete required for WORM bucket | MFA delete is incompatible with cross-account replication and S3 Object Lock (Object Lock supersedes it for COMPLIANCE mode); not applicable here |
| Lambda CloudWatch log group for OIDC events is encrypted | Unencrypted (same issue as M3 for SSM logs); existing finding M3 covers all log groups |

---

## Summary of New Findings in This Audit

| ID | Severity | Title | File | Line |
|---|---|---|---|---|
| — (new) | HIGH | Object Lock Not Enabled at Bucket Creation | `deploy/regional/s3.tf` | 2 |
| — (new) | MEDIUM | S3 Lifecycle Rule Deletes Delete Markers in WORM Bucket | `deploy/regional/s3.tf` | 102 |
| — (new) | MEDIUM | Cross-Account Replication Optional, No Prod Enforcement | `deploy/regional/s3.tf` | 60 |
| — (new) | LOW | Lambda Invocation Log Retention Too Short for FedRAMP Audit | `deploy/regional/lambda-create-investigation.tf` | 4 |
| — (new) | LOW | Residual Per-Investigation Task Definition Metadata in ECS Registry | `lambda/create-investigation/handler.py` | 479 |

**Cross-references to existing findings:** M3 (CloudWatch encryption), M4 (SSE-S3 vs KMS), M6 (no TLS bucket policy), M13 (PutObjectAcl in task role), M25 (DescribeTaskDefinition scope), M29 (symlink traversal in s3 sync), C1 (cross-user S3 read), L10 (log retention), H1 (missing CloudTrail/GuardDuty).
