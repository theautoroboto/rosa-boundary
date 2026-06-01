# Security Action Plan — HIGH & CRITICAL Findings

**Date:** 2026-06-01
**Sources:** All docs in `docs/security/` (lambda, infrastructure, data-handling, tamper-resistance, abac, auth-chain, container audits)
**Scope:** HIGH and CRITICAL findings only. MEDIUM/LOW findings are captured in the individual audit documents.

---

## Finding Inventory

| ID | Severity | Title | Source Doc | File |
|---|---|---|---|---|
| C1 | Critical | Task role S3 GetObject unrestricted — any SRE reads any other SRE's audit data | abac-audit, infra-audit | `iam.tf:124` |
| WORM | Critical | Object Lock not enabled at bucket creation — WORM protection ineffective | data-handling-audit | `s3.tf:2` |
| H10 | High | Missing access point ownership check — any SRE can mount another user's EFS | lambda-audit | `handler.py:586` |
| H7 | High | Group membership enforced only at app layer — any Keycloak user can assume SRE role directly | infra-audit, auth-chain | `oidc.tf:88` |
| H3 | High | DescribeAndListECS has no ownership condition — all SREs enumerate all tasks/definitions | infra-audit, abac-audit | `oidc.tf:201` |
| H8 | High | SSMSessionForECSExec has no ownership condition — direct ABAC bypass path | infra-audit, abac-audit | `oidc.tf:212` |
| H5 | High | task_timeout=0 accepted — permanent sessions that reaper IAM cannot stop | infra-audit, lambda-audit | `handler.py:141`, `lambda-reap-tasks.tf:68` |
| H4 | High | NOPASSWD sudo enables kill -9 to bypass S3 audit sync | tamper-audit, container-audit | `Containerfile:66` |
| H1 | High | No CloudTrail or GuardDuty — no audit of API calls or threat detection | infra-audit | `main.tf` |
| H2 | High | Lambda not in VPC — JWKS fetched over public internet | infra-audit | `lambda-create-investigation.tf:114` |
| H9 | High | KMS key ECS service principal lacks SourceArn — any Fargate task can decrypt exec sessions | infra-audit, abac-audit | `kms.tf:36` |
| REAPER-NET | High | Reaper network exception aborts all remaining task processing in batch | tamper-audit | `handler.py:117` |
| SYNC-TIMEOUT | High | S3 sync has no timeout — large /home/sre directories will be SIGKILL'd mid-transfer | tamper-audit | `entrypoint.sh:28` |

---

## Work Streams

Findings are grouped by the team/component responsible and ordered within each group by risk.

---

## Stream 1: Terraform / IAM — Authorization Boundaries

**Owner:** Platform/Infrastructure team
**Priority:** Immediate — these are the root causes of the most severe exploitation chains.

### 1.1 Add group membership condition to SRE role trust policy (H7)

The `sre_shared` and `lambda_invoker` role trust policies condition only on `aud`. Any Keycloak user can assume the SRE role directly without invoking the Lambda, bypassing group membership enforcement.

**File:** `deploy/regional/oidc.tf:88–143`, `deploy/regional/lambda-invoker.tf:13–62`

```hcl
# In the sre_shared and lambda_invoker trust policies, add:
Condition = {
  StringEquals = {
    "${local.oidc_provider_domain}:aud" = var.oidc_client_id
  }
  "ForAnyValue:StringEquals" = {
    "${local.oidc_provider_domain}:groups" = var.required_groups
  }
}
```

Requires Keycloak to include a `groups` claim via a protocol mapper. The claim name must match exactly what is used in the condition.

---

### 1.2 Scope S3 task role to per-investigation prefix only (C1)

The task IAM role grants `s3:GetObject` and `s3:ListBucket` on the entire audit bucket. Any SRE container can read any other investigation's artifacts.

**File:** `deploy/regional/iam.tf:124–143`

Remove `s3:GetObject` from the static task role entirely. The per-investigation task definition registered by the Lambda (`register_investigation_task_definition`) should inject a tightly scoped inline policy at registration time, or the task role resource ARN should be scoped with a prefix condition:

```hcl
# Replace the existing s3-audit-access Statement with:
{
  Effect = "Allow"
  Action = ["s3:PutObject"]
  Resource = "${aws_s3_bucket.audit.arn}/*"
},
{
  Effect = "Allow"
  Action = ["s3:ListBucket"]
  Resource = aws_s3_bucket.audit.arn
  Condition = {
    StringLike = {
      "s3:prefix" = ["$${aws:PrincipalTag/cluster_id}/$${aws:PrincipalTag/investigation_id}/*"]
    }
  }
}
```

Also remove `s3:PutObjectAcl` — `s3:PutObject` is sufficient for audit sync.

---

### 1.3 Add ownership condition to DescribeAndListECS (H3)

All SREs can enumerate all running tasks and task definitions in the cluster, exposing other users' investigation metadata, kubeconfig secret ARNs, and cluster IDs.

**File:** `deploy/regional/oidc.tf:201–210`

```hcl
{
  Sid    = "ListAndDescribeOwnTasks"
  Effect = "Allow"
  Action = ["ecs:ListTasks", "ecs:DescribeTasks"]
  Resource = [
    aws_ecs_cluster.main.arn,
    "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
  ]
  Condition = {
    StringEquals = {
      "ecs:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}"
    }
  }
}
```

Remove `ecs:DescribeTaskDefinition` from the SRE role entirely — it is not required by the `join-task` or `start-task` workflows.

---

### 1.4 Scope SSM StartSession resource and add ownership condition (H8)

`ssm:StartSession` is granted on any ECS task in any region or account, with no tag condition. Combined with the unrestricted `DescribeTasks`, an SRE can obtain another user's container runtime ID and open an SSM session directly, bypassing the ABAC gate on `ecs:ExecuteCommand`.

**File:** `deploy/regional/oidc.tf:212–221`

```hcl
{
  Sid    = "SSMSessionForECSExec"
  Effect = "Allow"
  Action = ["ssm:StartSession"]
  Resource = [
    "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*",
    "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-StartInteractiveCommand"
  ]
}
```

Note: AWS does not evaluate `ecs:ResourceTag` conditions on `ssm:StartSession` actions. The most effective control is completing 1.3 first (restrict `DescribeTasks` to owned tasks), which eliminates the ability to discover other users' container runtime IDs.

---

### 1.5 Add SourceArn condition to KMS key ECS service principal (H9)

The KMS key policy grants `kms:Decrypt` and `kms:GenerateDataKey` to `ecs-tasks.amazonaws.com` without any `aws:SourceArn` condition. Any Fargate task in the account can use this key.

**File:** `deploy/regional/kms.tf:36–48`

```hcl
{
  Sid    = "Allow ECS Exec"
  Effect = "Allow"
  Principal = { Service = "ecs-tasks.amazonaws.com" }
  Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
  Resource  = "*"
  Condition = {
    ArnLike    = { "aws:SourceArn" = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:cluster/${aws_ecs_cluster.main.name}" }
    StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
  }
}
```

Also scope `KMSForECSExec` in the SRE role from `Resource = "*"` to `Resource = aws_kms_key.exec_session.arn`.

---

### 1.6 Scope create-investigation Lambda ECS policy to cluster (M1)

The Lambda's ECS policy uses `Resource = "*"` with no cluster condition. A compromised Lambda can stop tasks or deregister task definitions in any ECS cluster in the account.

**File:** `deploy/regional/lambda-create-investigation.tf:44–55`

```hcl
{
  Effect = "Allow"
  Action = ["ecs:RunTask", "ecs:StopTask", "ecs:ListTasks", "ecs:TagResource"]
  Resource = [
    aws_ecs_cluster.main.arn,
    "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
  ]
  Condition = { StringEquals = { "ecs:cluster" = aws_ecs_cluster.main.arn } }
},
{
  Effect = "Allow"
  Action = ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"]
  Resource = "*"
}
```

(`RegisterTaskDefinition` cannot be resource-scoped by AWS IAM — `iam:PassRole` scoping to two project roles is the effective constraint.)

---

## Stream 2: Lambda / Application Code — Authorization Fixes

**Owner:** Application team
**Priority:** Immediate — direct exploitation paths for authenticated SREs.

### 2.1 Add access point ownership check in create-investigation handler (H10)

`find_existing_access_point()` runs unconditionally. If a caller supplies another user's `cluster_id`+`investigation_id`, the Lambda reuses their EFS access point with no ownership check — mounting the victim's `/home/sre` data into the attacker's task.

**File:** `lambda/create-investigation/handler.py:601–603`

```python
if existing_ap:
    # Verify ownership before reusing
    ap_tags = {t['Key']: t['Value'] for t in existing_ap.get('Tags', [])}
    ap_owner_sub = ap_tags.get('oidc_sub')
    if ap_owner_sub and ap_owner_sub != oidc_sub:
        raise PermissionError(
            f"Access point for investigation '{investigation_id}' belongs to a different user"
        )
    access_point_id = existing_ap['AccessPointId']
```

Add `PermissionError` handling in the outer try/except to return a 403 response.

---

### 2.2 Enforce minimum task_timeout — reject task_timeout=0 (H5)

The Lambda accepts `task_timeout=0`, which prevents the `deadline` tag from being set. The reaper's IAM policy requires a `deadline` tag to call `ecs:StopTask`, so these tasks are permanently exempt from reaper enforcement at the IAM level.

**File:** `lambda/create-investigation/handler.py:133–147`, `deploy/regional/lambda-reap-tasks.tf:68–72`

```python
# In handler.py, replace the current validation:
TASK_TIMEOUT_MIN = 300   # 5 minutes minimum
TASK_TIMEOUT_MAX = 86400
if task_timeout < TASK_TIMEOUT_MIN:
    return response(400, {
        'error': f'task_timeout must be at least {TASK_TIMEOUT_MIN} seconds (got {task_timeout})'
    })
```

Also remove the `ForAnyValue:StringLike: {ecs:ResourceTag/deadline: "*"}` condition from the reaper's `ecs:StopTask` statement in `lambda-reap-tasks.tf` — deadline enforcement is now an application-layer decision, not IAM-enforced.

---

### 2.3 Fix reaper to catch all exceptions on ecs.stop_task() (REAPER-NET)

A non-`ClientError` exception (network timeout, endpoint connection error) from `ecs.stop_task()` propagates to the outer except handler and aborts processing of all remaining tasks in the invocation. Tasks past their deadline continue running for another full schedule interval.

**File:** `lambda/reap-tasks/handler.py:117–127`

```python
# Change:
except ClientError as e:
# To:
except Exception as e:
    logger.error(f"Failed to stop task {task_id}: {str(e)}")
    errors += 1
```

This ensures a transient failure on one task does not abort processing for all remaining tasks in the batch.

---

## Stream 3: S3 / Audit Integrity — WORM and Evidence Preservation

**Owner:** Platform/Infrastructure team
**Priority:** High — WORM protection is currently ineffective; audit evidence can be lost.

### 3.1 Enable Object Lock at bucket creation (WORM)

The `aws_s3_bucket.audit` resource is missing `object_lock_enabled = true`. AWS requires Object Lock to be enabled at bucket creation. Without it, the `aws_s3_bucket_object_lock_configuration` resource's COMPLIANCE mode retention silently has no effect.

**File:** `deploy/regional/s3.tf:2`

```hcl
resource "aws_s3_bucket" "audit" {
  bucket              = local.bucket_name
  object_lock_enabled = true   # Must be at bucket creation
  tags                = local.common_tags

  lifecycle {
    prevent_destroy = true   # Protect WORM bucket from accidental deletion
  }
}
```

If the bucket already exists without Object Lock, it must be recreated. Enable Object Lock via the AWS Console one-time migration path first, then import the resource into Terraform.

---

### 3.2 Add a timeout to the S3 sync command (SYNC-TIMEOUT)

`aws s3 sync /home/sre` runs with no timeout. ECS sends SIGKILL 120 seconds after SIGTERM. For large investigation workspaces, the sync is interrupted mid-transfer.

**File:** `entrypoint.sh:28`

```bash
# Replace:
aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet || \
    echo "Warning: S3 sync failed" >&2

# With:
timeout 90 aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet \
    --no-follow-symlinks || \
    echo "Warning: S3 sync failed or timed out (check CloudWatch for partial upload)" >&2
```

The 90-second timeout gives the sync time to complete before ECS's 120-second SIGKILL. The `--no-follow-symlinks` flag also closes the M29 symlink exfiltration path simultaneously.

---

### 3.3 Add CloudTrail with S3 data events (H1)

No CloudTrail is defined. S3 object-level access (GetObject, PutObject, DeleteObject) on the audit bucket is not logged. Without data events, there is no record of who has read audit evidence or when.

**File:** `deploy/regional/main.tf` (new resource)

```hcl
resource "aws_cloudtrail" "main" {
  name                          = "${var.project}-${var.stage}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.exec_session.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.audit.arn}/"]
    }
  }
}

resource "aws_guardduty_detector" "main" {
  enable = true
}
```

---

## Stream 4: Container / Entrypoint — Audit Evasion

**Owner:** Container/Platform team
**Priority:** High — authenticated SREs can evade audit by bypassing S3 sync.

### 4.1 Restrict sudo to alternatives only — remove NOPASSWD: ALL (H4)

The `sre` user has `NOPASSWD: ALL` sudo. This allows `sudo kill -9 1` to send SIGKILL to the entrypoint (PID 1), which cannot be trapped, bypassing the SIGTERM handler that triggers S3 sync.

**File:** `Containerfile:66`

```dockerfile
# Replace:
RUN echo "sre ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/sre

# With:
RUN echo "sre ALL=(root) NOPASSWD: /usr/sbin/alternatives, /usr/bin/alternatives" \
    > /etc/sudoers.d/sre && chmod 440 /etc/sudoers.d/sre
```

Update `entrypoint.sh` to call `sudo alternatives --set ...` instead of running as root. Verify that no other entrypoint path requires broad root access.

---

### 4.2 Add continuous background S3 sync (H4 partial mitigation)

Even with restricted sudo, an operator-level SIGKILL (ECS stop timeout exceeded) can interrupt exit-time sync. A background sync running every 60 seconds limits the maximum audit loss window.

**File:** `entrypoint.sh`

```bash
# Add after the main command is launched in the background:
if [ -n "${S3_AUDIT_ESCROW}" ]; then
    while true; do
        sleep 60
        aws s3 sync /home/sre "${S3_AUDIT_ESCROW}" --quiet \
            --no-follow-symlinks 2>/dev/null || true
    done &
    SYNC_PID=$!
fi
```

Kill `$SYNC_PID` in `cleanup()` after the final sync completes.

---

## Stream 5: Networking — VPC Isolation

**Owner:** Infrastructure team
**Priority:** High — required for FedRAMP SC-7 boundary protection.

### 5.1 Deploy Lambda inside VPC (H2)

The create-investigation Lambda has no `vpc_config`. JWKS endpoint fetching and all AWS API calls egress over the public internet.

**File:** `deploy/regional/lambda-create-investigation.tf:114–158`

```hcl
resource "aws_lambda_function" "create_investigation" {
  # ... existing config ...
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }
}

resource "aws_security_group" "lambda" {
  name   = "${var.project}-${var.stage}-lambda"
  vpc_id = var.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

Add VPC Interface Endpoints for `ecs`, `elasticfilesystem`, `sts`, `secretsmanager`, and `logs` to keep AWS API calls off the public internet. VPC-deployed Lambdas require a NAT gateway or VPC endpoints for internet-bound traffic (Keycloak JWKS).

---

## Remediation Priority Matrix

| Priority | Stream | Items | Rationale |
|---|---|---|---|
| **P0 — Do first** | IAM | 1.1 (group enforcement), 1.2 (S3 scope) | Closes the two widest exploitation paths; any Keycloak user can assume SRE role today; C1 is directly exploitable without privilege escalation |
| **P0 — Do first** | Lambda | 2.1 (EFS ownership check), 2.2 (timeout=0) | New high-severity findings; directly exploitable by any SRE |
| **P0 — Do first** | S3 | 3.1 (Object Lock) | WORM protection is currently non-functional; must recreate bucket |
| **P1 — This sprint** | IAM | 1.3 (DescribeTasks scope), 1.4 (SSM scope), 1.5 (KMS SourceArn) | Close the task enumeration and ABAC bypass chains; require 1.1 to be in place first |
| **P1 — This sprint** | Lambda | 2.3 (reaper exception handling) | Deadline enforcement gap; moderate operational impact |
| **P1 — This sprint** | Entrypoint | 3.2 (sync timeout + --no-follow-symlinks) | Closes M29 and reduces SIGKILL sync loss simultaneously |
| **P2 — Next sprint** | CloudTrail | 3.3 (CloudTrail + GuardDuty) | FedRAMP AU-2 requirement; no detection without it |
| **P2 — Next sprint** | Container | 4.1 (restrict sudo), 4.2 (background sync) | Audit evasion; requires container rebuild and deploy |
| **P3 — Planned** | Networking | 5.1 (Lambda VPC) | FedRAMP SC-7; significant infrastructure change; VPC endpoints add cost |
| **P3 — Planned** | IAM | 1.6 (Lambda ECS cluster scope) | Defense-in-depth; lower urgency than P0/P1 items |

---

## Dependency Map

```
1.1 (group enforcement) ──► must precede all other IAM fixes
                              (adds group check at IAM layer)

1.3 (DescribeTasks scope) ──► must precede 1.4 (SSM fix)
                               (eliminates the runtimeId discovery path
                               that makes H8 exploitable)

2.2 (reject timeout=0) ──► must precede removing reaper IAM condition
                            (application layer must enforce minimum
                            before IAM condition can be safely removed)

3.1 (Object Lock) ──► requires bucket recreation
                       coordinate with ops for data migration plan

4.1 (restrict sudo) ──► must precede 4.2 (background sync)
                         (background sync loop runs as sre; verify
                         alternatives still works with scoped sudo)
```

---

## Acceptance Criteria

Each item is complete when:

1. **Code change** merged to `main` with the specific fix applied
2. **Test coverage** — for Lambda fixes, a unit test covering the new validation path; for Terraform, a `terraform plan` showing the condition or resource change
3. **Finding closed** in `adversary-findings.json` with `status: resolved` and the commit SHA
4. **No regression** — existing integration tests (`make test-localstack`) pass

For P0 items, an interim compensating control should be documented in the runbook if the fix cannot be deployed immediately (e.g., temporarily restricting the `sre_shared` role trust policy to a specific named IAM user while the OIDC group condition is being rolled out).
