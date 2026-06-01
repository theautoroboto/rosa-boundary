# Infrastructure Configuration Audit

**Date:** 2026-06-01
**Scope:** Terraform IAM, S3, EFS, KMS, CloudWatch, VPC/Security Groups
**Branch:** `security_assessment`
**Machine-readable findings:** `adversary-findings.json` (cross-referenced IDs listed per finding)
**Jira:** [ROSAENG-305](https://redhat.atlassian.net/browse/ROSAENG-305)

**Files reviewed:**
- `deploy/regional/iam.tf`
- `deploy/regional/s3.tf`
- `deploy/regional/efs.tf`
- `deploy/regional/kms.tf`
- `deploy/regional/main.tf`
- `deploy/regional/variables.tf`
- `deploy/regional/ecs.tf`
- `deploy/regional/lambda-create-investigation.tf`
- `deploy/regional/lambda-reap-tasks.tf`
- `deploy/regional/lambda-invoker.tf`
- `deploy/regional/oidc.tf`
- `deploy/regional/outputs.tf`

---

## IAM

### CRITICAL — ECS Task Role Grants Unrestricted Audit Bucket Read to All Task Holders

**Finding ID:** C1 (`adversary-findings.json`)
**File:** `deploy/regional/iam.tf:124–143`

**Description:** The task role policy at lines 124–143 grants `s3:GetObject`, `s3:ListBucket`, `s3:PutObject`, and `s3:PutObjectAcl` on `aws_s3_bucket.audit.arn` and `${aws_s3_bucket.audit.arn}/*` with no path-prefix condition. Investigation data is written to per-investigation prefixes (`s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`), but the IAM policy grants read access to every object in the bucket.

**Impact:** Any container holding the task role credentials (available at `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) can enumerate and download investigation artifacts belonging to any other SRE. Alice can run `aws s3 ls s3://audit-bucket/bob-cluster/ --recursive` and retrieve Bob's complete investigation artifacts without any privilege escalation.

**Fix:** Scope `s3:GetObject` and `s3:ListBucket` to the caller's investigation prefix. Since per-investigation task definitions are registered by the Lambda with `CLUSTER_ID` and `INVESTIGATION_ID` as environment variables, the Lambda can scope the inline policy at task definition registration time. For the static task definition in Terraform, limit `s3:PutObject` only to the bucket scope without `s3:GetObject`:

```hcl
# In iam.tf — task_s3 policy
Statement = [
  {
    # Write access: scoped to own investigation prefix dynamically at Lambda registration
    Effect = "Allow"
    Action = ["s3:PutObject"]
    Resource = "${aws_s3_bucket.audit.arn}/*"
  },
  {
    # List access: no path condition — tighten at task-definition registration in Lambda
    Effect = "Allow"
    Action = ["s3:ListBucket"]
    Resource = aws_s3_bucket.audit.arn
    Condition = {
      StringLike = {
        "s3:prefix" = ["$${aws:PrincipalTag/cluster_id}/$${aws:PrincipalTag/investigation_id}/*"]
      }
    }
  }
]
```

Remove `s3:PutObjectAcl` and `s3:GetObject` from the static task role entirely (see also M13 below).

---

### HIGH — Lambda Create-Investigation ECS Policy Uses Wildcard Resource

**Finding ID:** M1 (`adversary-findings.json`)
**File:** `deploy/regional/lambda-create-investigation.tf:36–67`

**Description:** The `ecs-task-management` policy grants `ecs:RunTask`, `ecs:StopTask`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:DescribeTaskDefinition`, `ecs:RegisterTaskDefinition`, `ecs:DeregisterTaskDefinition`, and `ecs:TagResource` on `Resource = "*"`. The reap-tasks Lambda correctly scopes equivalent operations to the project cluster ARN with a `StringEquals: ecs:cluster` condition.

**Impact:** A compromised Lambda (e.g., via OIDC bypass or supply chain attack) can stop tasks across any ECS cluster in the account, deregister task definitions from unrelated workloads, and tag arbitrary resources.

**Fix:** Add a `StringEquals: ecs:cluster` condition to all statements that support it, and scope `DescribeTasks`/`StopTask` to the cluster task ARN prefix. Note that `RegisterTaskDefinition` and `DeregisterTaskDefinition` cannot be resource-scoped by AWS IAM; the `iam:PassRole` scope to only two project roles is the effective constraint for those actions (see also M31 for the task definition family condition approach):

```hcl
{
  Effect = "Allow"
  Action = ["ecs:RunTask", "ecs:StopTask", "ecs:ListTasks", "ecs:TagResource"]
  Resource = [
    aws_ecs_cluster.main.arn,
    "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
  ]
  Condition = {
    StringEquals = {
      "ecs:cluster" = aws_ecs_cluster.main.arn
    }
  }
},
{
  Effect = "Allow"
  Action = ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"]
  Resource = "*"
  Condition = {
    StringLike = {
      "ecs:TaskDefinitionFamily" = "${var.project}-${var.stage}-*"
    }
  }
}
```

---

### HIGH — Group Membership Enforced Only at Application Layer

**Finding ID:** H7 (`adversary-findings.json`)
**Files:** `deploy/regional/oidc.tf:88–143`, `deploy/regional/lambda-invoker.tf:13–62`

**Description:** Both the `sre_shared` role and `lambda_invoker` role trust policies condition only on `<oidc_provider_domain>:aud == oidc_client_id`. Group membership (`sre-team`, etc.) is checked exclusively inside the Lambda handler — any Keycloak user with a valid token for the correct audience can assume `sre_shared` via a direct STS call without invoking the Lambda.

**Impact:** Any Keycloak user (developers, contractors, former employees with live accounts) can enumerate all running SRE tasks and their metadata (cluster IDs, investigation IDs, OIDC subjects) by assuming `sre_shared` and calling `ecs:ListTasks`/`ecs:DescribeTasks` directly. Task exec is still ABAC-gated, but the information disclosure risk is significant.

**Fix:** Add a group membership condition to both trust policies. Keycloak must include a `groups` claim via a groups protocol mapper:

```hcl
Condition = {
  StringEquals = {
    "${local.oidc_provider_domain}:aud" = var.oidc_client_id
  }
  "ForAnyValue:StringEquals" = {
    "${local.oidc_provider_domain}:groups" = var.required_groups
  }
}
```

---

### HIGH — ABAC Task Enumerate/Describe Has No Ownership Condition

**Finding ID:** H3 (`adversary-findings.json`)
**File:** `deploy/regional/oidc.tf:201–210`

**Description:** The `DescribeAndListECS` statement grants `ecs:DescribeTasks`, `ecs:ListTasks`, and `ecs:DescribeTaskDefinition` on `Resource = "*"` with no conditions. Any authenticated SRE can enumerate all tasks and task definitions in the cluster, including those belonging to other users.

**Impact:** Any SRE can determine which users are running active investigations, which clusters they are investigating, their session timeout values, their OIDC subjects (from task tags), and the Secrets Manager ARN for the cluster kubeconfig (from task definition environment variables). This is a concrete prerequisite for several other attacks (H6 — stop/close other's task; H8 — SSM session bypass; C1 — S3 read using known prefix).

**Fix:** Scope `ecs:ListTasks` and `ecs:DescribeTasks` to tasks matching the caller's ABAC tag:

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

Remove `ecs:DescribeTaskDefinition` from the SRE role entirely. The join-task workflow does not require it.

---

### HIGH — SSM StartSession Has No Ownership Condition — Direct ABAC Bypass

**Finding ID:** H8 (`adversary-findings.json`)
**File:** `deploy/regional/oidc.tf:212–221`

**Description:** The `SSMSessionForECSExec` statement grants `ssm:StartSession` on `arn:aws:ecs:*:*:task/*` (any ECS task in any region or account) with no tag condition. An SRE with `sre_shared` role credentials can call `ssm:StartSession` directly with a manually constructed target string (`ecs:<cluster>_<taskId>_<runtimeId>`) to enter any ECS task, bypassing the `ecs:ExecuteCommand` ABAC check — since the ABAC condition is only on the `ecs:ExecuteCommand` IAM action, and SSM doesn't inspect ECS resource tags.

**Impact:** Alice calls `ecs:DescribeTasks` on Bob's task (permitted by the unconditioned `DescribeAndListECS`), obtains the `containerRuntimeId`, constructs the SSM target string, and runs `aws ssm start-session --target ecs:cluster_taskid_runtimeid --document-name AWS-StartInteractiveCommand --parameters command=/bin/bash`. The ABAC ownership model is completely bypassed.

**Fix:** At minimum, scope the SSM resource to the specific cluster and region to eliminate cross-account and cross-region access, and add an ABAC tag condition:

```hcl
{
  Sid    = "SSMSessionForECSExec"
  Effect = "Allow"
  Action = ["ssm:StartSession"]
  Resource = [
    "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*",
    "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-StartInteractiveCommand"
  ]
  Condition = {
    StringEquals = {
      "ecs:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}"
    }
  }
}
```

Note: The SSM API itself does not evaluate ECS resource tags; the `ecs:ResourceTag` condition in an `ssm:StartSession` IAM statement is not enforced by AWS IAM evaluation. True defense requires AWS to extend SSM resource tagging — in the interim, the most effective control is restricting `ecs:DescribeTasks` to owned tasks (H3 fix) so the `containerRuntimeId` is not obtainable by other SREs in the first place.

---

### HIGH — KMS Key Policy ECS Exec Principal Lacks SourceArn Condition

**Finding ID:** H9 (`adversary-findings.json`)
**File:** `deploy/regional/kms.tf:36–48`

**Description:** The KMS key policy's `Allow ECS Exec` statement grants `kms:Decrypt` and `kms:GenerateDataKey` to `Principal: {Service: ecs-tasks.amazonaws.com}` with no `aws:SourceArn` or `aws:SourceAccount` condition. Any Fargate task in the account — regardless of workload — can use this key if it knows the ARN.

**Impact:** If another ECS workload in the same account is compromised, it can use this key to decrypt ECS Exec session data. When CloudWatch log encryption is enabled (M3 remediation), SREs can also call `kms:Decrypt` directly (permitted by the overly broad `KMSForECSExec` in the SRE role, see M2) to decrypt other SREs' SSM session logs outside of CloudWatch's own access controls.

**Fix:**

```hcl
{
  Sid    = "Allow ECS Exec"
  Effect = "Allow"
  Principal = {
    Service = "ecs-tasks.amazonaws.com"
  }
  Action = ["kms:Decrypt", "kms:GenerateDataKey"]
  Resource = "*"
  Condition = {
    ArnLike = {
      "aws:SourceArn" = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:cluster/${aws_ecs_cluster.main.name}"
    }
    StringEquals = {
      "aws:SourceAccount" = data.aws_caller_identity.current.account_id
    }
  }
}
```

---

### MEDIUM — Shared SRE Role KMS Statement Allows Decrypt on All Keys

**Finding ID:** M2 (`adversary-findings.json`)
**File:** `deploy/regional/oidc.tf:222–230`

**Description:** The `KMSForECSExec` statement grants `kms:Decrypt` and `kms:GenerateDataKey` on `Resource = "*"`. The ECS task role (`iam.tf:224`) correctly scopes these permissions to `aws_kms_key.exec_session.arn`.

**Impact:** Any SRE holding the shared role can decrypt data encrypted with any KMS key in the account (subject to key policy), including any future CMK created for EFS, S3, or other services. When M3 is remediated with CloudWatch encryption enabled, this grants direct decryption of other SREs' session logs.

**Fix:**

```hcl
Resource = aws_kms_key.exec_session.arn
```

---

### MEDIUM — Lambda Missing elasticfilesystem:DeleteAccessPoint for Error Cleanup

**Finding ID:** M12 (`adversary-findings.json`)
**File:** `deploy/regional/lambda-create-investigation.tf:70–88`

**Description:** The Lambda's EFS IAM policy (`efs-access-point-management`) grants only `CreateAccessPoint`, `DescribeAccessPoints`, and `TagResource`. The Lambda handler calls `efs.delete_access_point()` in four error-cleanup paths (handler.py lines 671, 727, 756, 782). These calls silently fail with `AccessDeniedException` because the permission is not granted. The bare `except Exception: pass` blocks swallow the failures.

**Impact:** Every failed task launch after a new EFS access point was created leaves an orphaned access point. The EFS access point limit is 10,000 per filesystem. In a failure storm or sustained attack, this limit could be reached, preventing all new investigation creation.

**Fix:**

```hcl
resource "aws_iam_role_policy" "create_investigation_lambda_efs" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DeleteAccessPoint",   # Add this
        "elasticfilesystem:TagResource"
      ]
      Resource = aws_efs_file_system.sre_home.arn
    }]
  })
}
```

---

### MEDIUM — ECS Task Role Grants s3:PutObjectAcl on Audit Bucket

**Finding ID:** M13 (`adversary-findings.json`)
**File:** `deploy/regional/iam.tf:131–137`

**Description:** The ECS task role's S3 policy includes `s3:PutObjectAcl`. Although `block_public_acls = true` prevents public ACL grants, cross-account ACL grants are not blocked by the public access block settings.

**Impact:** An SRE container can grant read access to an attacker-controlled AWS account's canonical user on audit log objects, making audit evidence readable externally without using the S3 bucket policy or IAM.

**Fix:** Remove `s3:PutObjectAcl` from the task role. The audit sync only needs `s3:PutObject`.

---

### MEDIUM — Bedrock IAM Policy Allows All Regions and All Foundation Models

**Finding ID:** M10 (`adversary-findings.json`)
**File:** `deploy/regional/iam.tf:155–165`

**Description:** The Bedrock policy grants `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on `arn:aws:bedrock:*:*:inference-profile/*` and `arn:aws:bedrock:*:*:foundation-model/*`. The wildcard region and all-model access are broader than necessary.

**Impact:** A compromised container can invoke expensive models in any region (cost abuse) and may route data to Bedrock endpoints outside FedRAMP-authorized US regions, violating data residency requirements.

**Fix:**

```hcl
Resource = [
  "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/anthropic.claude-*",
  "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/*"
]
```

---

### MEDIUM — ECS Task and Lambda Roles Lack Confused Deputy Protection

**Finding ID:** M11 (`adversary-findings.json`)
**Files:** `deploy/regional/iam.tf:106–121`, `deploy/regional/lambda-create-investigation.tf:12–27`

**Description:** The ECS task role, execution role, and both Lambda execution roles use bare service principal trust policies (`Principal: {Service: ecs-tasks.amazonaws.com}` or `lambda.amazonaws.com`) without `aws:SourceAccount` or `aws:SourceArn` conditions.

**Impact:** Any Lambda or ECS task in the account (not just this project's) could attempt to assume these roles if granted `sts:AssumeRole` through another policy path, weakening cross-workload isolation in a shared account.

**Fix:** Add source conditions to all service principal trust policies:

```hcl
Condition = {
  StringEquals = {
    "aws:SourceAccount" = data.aws_caller_identity.current.account_id
  }
  ArnLike = {
    "aws:SourceArn" = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
  }
}
```

---

### LOW — Execution Role Secrets Manager Wildcard Covers All Project Secrets

**File:** `deploy/regional/iam.tf:87–102`

**Description:** The execution role's Secrets Manager policy at line 99 grants access to `arn:aws:secretsmanager:...:secret:${var.project}/*`. This means the ECS execution role can access any secret under the `rosa-boundary/` prefix namespace, including secrets added in the future. The current use is cluster kubeconfig secrets (`rosa-boundary/clusters/<cluster_id>/kubeconfig`), but the policy implicitly pre-authorizes future secrets added by other operators or modules.

**Impact:** If a new secret is added under the `rosa-boundary/` prefix (e.g., an API key or database credential for a future component), the ECS execution role automatically gains access to it without any IAM change being required or reviewed. This is a least-privilege gap that grows over time.

**Fix:** Scope to the specific secret name pattern used for kubeconfig:

```hcl
Resource = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project}/clusters/*/kubeconfig*"
```

---

### LOW — Invoker Role sts:TagSession Is Inert — Session Tags Are Unused

**Finding ID:** L18 (`adversary-findings.json`)
**File:** `deploy/regional/lambda-invoker.tf:21–26`

**Description:** The `lambda_invoker` role trust policy allows `sts:TagSession`. This causes session tags from the JWT's `https://aws.amazon.com/tags` claim to be applied to the invoker role session. However, the invoker role's permissions policy grants only `lambda:InvokeFunction` — it has no tag-conditioned statements. The session tags are set and then completely ignored.

**Impact:** Misleads future reviewers into believing the invoker role enforces ABAC. The `sts:TagSession` permission technically allows the caller to inject arbitrary session tags into the invoker role session (up to STS limits), which are recorded in CloudTrail and could pollute audit logs.

**Fix:** Remove `sts:TagSession` from the invoker trust policy and add a comment explaining it is intentionally absent:

```hcl
# sts:TagSession is intentionally omitted: the invoker role has no tag-conditioned
# statements. Session tags from the JWT are only meaningful on sre_shared, where
# they enforce ABAC (ecs:ResourceTag matching aws:PrincipalTag).
Action = ["sts:AssumeRoleWithWebIdentity"]
```

---

## S3

### MEDIUM — S3 Audit Bucket Uses SSE-S3 Instead of SSE-KMS

**Finding ID:** M4 (`adversary-findings.json`)
**File:** `deploy/regional/s3.tf:47–50`

**Description:** The audit bucket uses `sse_algorithm = "AES256"` (SSE-S3), not `aws:kms`. SSE-S3 uses AWS-managed keys that cannot be restricted via key policy, provide no CloudTrail audit of key usage, and cannot be rotated on demand.

**Impact:** For a WORM audit log bucket under FedRAMP SC-28, there is no separate `kms:Decrypt` authorization gate. Any principal with `s3:GetObject` can read objects with no additional KMS check. Key usage is not audited in CloudTrail KMS data events.

**Fix:** Create a dedicated KMS CMK for the audit bucket:

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit_bucket.arn
    }
    bucket_key_enabled = true
  }
}
```

---

### MEDIUM — No S3 Bucket Policy Enforcing Encryption in Transit (Deny Non-TLS)

**Finding ID:** M6 (`adversary-findings.json`)
**File:** `deploy/regional/s3.tf:1`

**Description:** No `aws_s3_bucket_policy` enforces TLS on the audit bucket. SDK misconfigurations or internal tooling could access objects over unencrypted HTTP.

**Impact:** FedRAMP SC-8 (Transmission Confidentiality and Integrity) and CIS AWS Foundations Benchmark 2.1.2 both require a deny-non-TLS bucket policy. Without it, a misconfigured SDK or script can exfiltrate audit data in plaintext.

**Fix:**

```hcl
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
```

---

### LOW — No S3 Server Access Logging on Audit Bucket

**File:** `deploy/regional/s3.tf:1`

**Description:** The audit S3 bucket has no `aws_s3_bucket_logging` resource configured. Server access logs record every request to the bucket (GetObject, PutObject, DeleteObject, ListBucket), including the requester's IP address, request ID, and IAM identity. Without access logs, there is no record of who has read audit objects, when, and from where.

**Impact:** FedRAMP AU-2 (Event Logging) and AU-14 (Session Audit) require that access to audit records is itself logged. If an insider reads audit evidence from the S3 bucket (using the task role's unrestricted `s3:GetObject` — see C1), there is no S3-level audit of that access. CloudTrail management events do not include S3 object-level data events by default; data events must be explicitly enabled (a gap captured in H1, but separate from access log coverage).

**Fix:**

```hcl
resource "aws_s3_bucket_logging" "audit" {
  bucket        = aws_s3_bucket.audit.id
  target_bucket = aws_s3_bucket.audit.id  # Self-logging or dedicated logs bucket
  target_prefix = "access-logs/"
}
```

For a FedRAMP environment, prefer a dedicated, separate S3 bucket for access logs to avoid access log entries appearing in the same WORM-protected bucket (where they would themselves be locked under Object Lock).

---

### LOW — S3 Lifecycle Rule Does Not Expire Noncurrent Object Versions

**File:** `deploy/regional/s3.tf:102–119`

**Description:** The lifecycle rule (`cleanup-old-versions`) handles only expired delete markers and incomplete multipart uploads. It does not include a `noncurrent_version_expiration` rule. With versioning enabled (required for Object Lock) and COMPLIANCE mode Object Lock, overwritten objects create noncurrent versions. Those noncurrent versions are not subject to the Object Lock default retention rule unless they are also individually locked. Without noncurrent version expiration, storage costs grow unbounded as audit objects are rewritten (e.g., during S3 sync re-uploads).

**Impact:** This is primarily a cost and operational hygiene concern rather than a direct security vulnerability. However, over time the volume of unmanaged noncurrent versions could obscure the audit record by making it unclear which version is the authoritative audit artifact. It could also cause storage quota concerns in a regulated environment.

**Fix:** Add a noncurrent version expiration rule with a value equal to or greater than `var.retention_days` to ensure noncurrent versions are retained at least as long as the Object Lock retention period:

```hcl
rule {
  id     = "expire-old-versions"
  status = "Enabled"

  noncurrent_version_expiration {
    noncurrent_days = var.retention_days
  }
}
```

---

## EFS

### MEDIUM — No EFS Filesystem Policy — Anonymous NFS Mount Not Explicitly Denied

**Finding ID:** M5 (`adversary-findings.json`)
**File:** `deploy/regional/efs.tf:1`

**Description:** There is no `aws_efs_file_system_policy` resource. While the ECS task definition correctly enables IAM authorization on the access point (`iam = "ENABLED"`) and transit encryption (`transit_encryption = "ENABLED"`), the filesystem itself does not have a resource policy that denies direct NFS mounts without an access point or enforces IAM authentication.

**Impact:** Any entity with network access to NFS port 2049 on the mount targets can attempt to mount the filesystem directly (root squash only prevents privilege escalation, not anonymous mounts). If the Fargate security group or VPC network ACLs are misconfigured, an attacker with VPC access can bypass access point isolation and access the raw EFS filesystem as root.

**Fix:**

```hcl
resource "aws_efs_file_system_policy" "sre_home" {
  file_system_id = aws_efs_file_system.sre_home.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceAccessPointAndIAM"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
        Resource  = aws_efs_file_system.sre_home.arn
        Condition = {
          Bool = {
            "elasticfilesystem:AccessedViaMountTarget" = "true"
          }
          StringEquals = {
            "aws:PrincipalType" = "AWS"
          }
        }
      },
      {
        Sid       = "DenyDirectMount"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "elasticfilesystem:*"
        Resource  = aws_efs_file_system.sre_home.id
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
```

---

### MEDIUM — EFS Filesystem Uses AWS-Managed Key, Not a CMK

**Finding ID:** M14 (`adversary-findings.json`)
**File:** `deploy/regional/efs.tf:2–4`

**Description:** `encrypted = true` without a `kms_key_id` attribute causes EFS to use the `aws/elasticfilesystem` AWS-managed key. AWS-managed keys cannot have custom key policies, cannot be rotated on demand, and do not generate separate CloudTrail KMS data events.

**Impact:** FedRAMP SC-28 requires independent key management control. Any principal with `elasticfilesystem:ClientMount` can decrypt EFS data without a separate `kms:Decrypt` gate. On-demand key rotation (NIST SP 800-57 recommendation) is impossible with AWS-managed keys.

**Fix:**

```hcl
resource "aws_kms_key" "efs_sre_home" {
  description             = "KMS CMK for EFS SRE home filesystem encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  # ... key policy granting EFS service principal with SourceArn condition ...
}

resource "aws_efs_file_system" "sre_home" {
  encrypted  = true
  kms_key_id = aws_kms_key.efs_sre_home.arn
  ...
}
```

---

### LOW — EFS Security Group Allows All Outbound Traffic

**Finding ID:** L2 (`adversary-findings.json`)
**File:** `deploy/regional/efs.tf:31–36`

**Description:** The EFS security group egress rule allows all traffic to `0.0.0.0/0` on all ports. EFS mount targets only respond to inbound NFS (port 2049) and do not initiate outbound connections.

**Impact:** Defense-in-depth: the unnecessary egress rule means if the security group is inadvertently attached to another resource or the EFS mount target behavior changes, outbound traffic is unrestricted.

**Fix:** Remove the egress block from the EFS security group entirely. Mount targets do not need outbound rules.

---

## KMS

### MEDIUM — KMS Key Deletion Window Is 7 Days — Minimum Allowed

**Finding ID:** M16 (`adversary-findings.json`)
**File:** `deploy/regional/kms.tf:4`

**Description:** `deletion_window_in_days = 7` is the AWS minimum. A scheduled deletion takes effect in 7 days, and all data encrypted with this key (ECS Exec session logs, CloudWatch logs once M3 is remediated) becomes permanently unreadable.

**Impact:** 7 days is insufficient detection and response time for a FedRAMP AU-11 audit record retention requirement (90 days online, 1 year offline). Accidental or malicious scheduling of key deletion renders WORM-protected audit evidence inaccessible.

**Fix:**

```hcl
resource "aws_kms_key" "exec_session" {
  deletion_window_in_days = 30   # AWS maximum
  ...
}
```

Also add a CloudWatch alarm on the `kms:ScheduleKeyDeletion` CloudTrail event for this key ARN.

---

### LOW — KMS Key Policy Root Principal Grants kms:* — No Admin/User Separation

**File:** `deploy/regional/kms.tf:10–18`

**Description:** The `Enable IAM User Permissions` statement at lines 10–18 grants `Action = "kms:*"` to the account root principal. This is the standard AWS approach for delegating key management to IAM, but it means that any IAM identity with `kms:*` permission (directly or transitively) can perform any key operation including `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:PutKeyPolicy`, and `kms:ImportKeyMaterial`. There is no explicit separation between key administrators (who can manage the key) and key users (who can use it for encrypt/decrypt).

**Impact:** Any over-privileged IAM role in the account (including an accidentally misconfigured automation role) with `kms:*` inherited through a `kms:*` or `*` IAM policy can disable or delete this key, rendering ECS Exec sessions non-functional and all encrypted log data inaccessible. For a FedRAMP system, separation of key administration from key use is a recommended control.

**Fix:** Replace the root delegation pattern with explicit administrator and user separation:

```hcl
{
  Sid    = "AllowKeyAdminByRootOnly"
  Effect = "Allow"
  Principal = {
    AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  }
  Action = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
    "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
    "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"
  ]
  Resource = "*"
}
```

Restrict `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey*`, and `kms:DescribeKey` to specific service principals and IAM roles only.

---

## CloudWatch Logs

### MEDIUM — ECS Exec Session Logs CloudWatch Encryption Disabled

**Finding ID:** M3 (`adversary-findings.json`)
**File:** `deploy/regional/ecs.tf:17`

**Description:** `cloud_watch_encryption_enabled = false` in the ECS cluster's execute command configuration. The `ssm_sessions` CloudWatch log group and all Lambda log groups also lack `kms_key_id` attributes.

**Impact:** SSM session logs contain the full command history and output of SRE investigations into production ROSA clusters, potentially including credential material, cluster access tokens, and sensitive diagnostic output. Without CMK encryption, any principal with CloudWatch `GetLogEvents` permission can read session logs without a separate KMS authorization check.

**Fix:**

```hcl
# In ecs.tf
log_configuration {
  cloud_watch_log_group_name     = aws_cloudwatch_log_group.ssm_sessions.name
  cloud_watch_encryption_enabled = true   # Enable
}

# Add kms_key_id to all sensitive log groups
resource "aws_cloudwatch_log_group" "ssm_sessions" {
  kms_key_id        = aws_kms_key.exec_session.arn
  retention_in_days = var.retention_days
}
```

---

### LOW — Default log_retention_days Is 7 Days — Insufficient for FedRAMP AU-11

**Finding ID:** L10 (`adversary-findings.json`)
**File:** `deploy/regional/variables.tf:88`

**Description:** `log_retention_days` defaults to 7 days. This applies to the Lambda CloudWatch log groups (`/aws/lambda/...`) and the ECS container log group (`/ecs/...`). Note that `ssm_sessions` correctly uses the separate `var.retention_days` (default 90 days).

**Impact:** Lambda invocation logs (OIDC validation errors, task creation events) are deleted after 7 days. FedRAMP AU-11 requires 90 days online retention minimum. An incident discovered after one week would have no supporting Lambda or container log evidence.

**Fix:**

```hcl
variable "log_retention_days" {
  default = 365   # FedRAMP minimum: 90 days; recommended: 365 days
}
```

---

## Networking

### HIGH — Lambda Not Deployed Inside VPC — JWKS Fetching Over Public Internet

**Finding ID:** H2 (`adversary-findings.json`)
**File:** `deploy/regional/lambda-create-investigation.tf:114–158`

**Description:** The create-investigation Lambda has no `vpc_config` block. It runs outside the VPC and fetches Keycloak JWKS endpoints over the public internet. No VPC Interface Endpoints are defined for Lambda, ECS, EFS, STS, or Secrets Manager, meaning all AWS API calls from the Lambda also egress over the public internet.

**Impact:** Token validation network path is uncontrolled. All AWS service API calls from the Lambda bypass VPC-level traffic inspection or network policies. FedRAMP SC-7 (Boundary Protection) requires controlled network boundaries for regulated workloads.

**Fix:**

```hcl
resource "aws_lambda_function" "create_investigation" {
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }
  ...
}
```

Add VPC Interface Endpoints for `ecr.api`, `ecr.dkr`, `ecs`, `elasticfilesystem`, `sts`, `secretsmanager`, and `logs` to keep Lambda traffic private. Add a dedicated security group for the Lambda allowing only outbound HTTPS (443) to the Keycloak endpoint and AWS service endpoints.

---

### HIGH — task_timeout=0 Disables Reaper Enforcement — Any SRE Can Create Permanent Sessions

**Finding ID:** H5 (`adversary-findings.json`)
**Files:** `lambda/create-investigation/handler.py:133–147`, `deploy/regional/lambda-reap-tasks.tf:63–73`

**Description:** The Lambda accepts `task_timeout` from the client request body (integer 0–86400). When `task_timeout=0`, no `deadline` tag is set on the ECS task. The reaper skips tasks without a `deadline` tag. Additionally, the reaper IAM `ecs:StopTask` policy has a `ForAnyValue:StringLike: {ecs:ResourceTag/deadline: "*"}` condition, meaning even a manual reaper invocation cannot stop deadline-less tasks.

**Impact:** Any authenticated SRE can bypass the tamper-proof timeout mechanism entirely, creating investigation sessions that run indefinitely. This undermines the ZOA bounded-session guarantee.

**Fix:** Enforce a minimum task timeout in the Lambda handler (remove `task_timeout=0` as valid input) and remove the IAM `ecs:StopTask` condition so the reaper can always stop expired tasks:

```python
# In handler.py — reject zero timeout
if task_timeout == 0:
    return response(400, {'error': 'task_timeout=0 is not permitted; minimum is 300 seconds'})
```

```hcl
# In lambda-reap-tasks.tf — remove the ForAnyValue condition
{
  Effect = "Allow"
  Action = ["ecs:StopTask"]
  Resource = "arn:aws:ecs:${region}:${account}:task/${cluster}/*"
  # No Condition — deadline enforcement is a handler-level decision
}
```

---

### MEDIUM — Lambda CORS Allows All Origins

**Finding ID:** M7 (`adversary-findings.json`)
**File:** `deploy/regional/lambda-create-investigation.tf:165–175`

**Description:** `allow_origins = ["*"]` in the Lambda function URL CORS configuration. A comment says "Allow localhost for testing; restrict in production" but this is not stage-gated.

**Impact:** Combined with `Access-Control-Allow-Headers: x-oidc-token`, any website can make a cross-origin POST to the Lambda function URL. While SigV4 prevents direct exploitation without valid AWS credentials, the wildcard CORS removes one defense-in-depth layer.

**Fix:** Restrict to known SRE tool domains:

```hcl
cors {
  allow_origins = var.stage == "prod" ? ["https://sre-portal.example.com"] : ["http://localhost:*"]
  allow_methods = ["POST"]
  allow_headers = ["content-type", "x-oidc-token"]
}
```

---

### HIGH — No CloudTrail or GuardDuty in Terraform Scope

**Finding ID:** H1 (`adversary-findings.json`)
**File:** `deploy/regional/main.tf:1`

**Description:** No `aws_cloudtrail`, `aws_guardduty_detector`, or `aws_config_*` resources are defined. There is no S3 data event trail for the audit bucket and no CloudTrail insights for API anomaly detection.

**Impact:** FedRAMP AU-2, AU-3, and AU-12 require capture of all security-relevant events. Without CloudTrail data events on the S3 audit bucket, access to WORM audit evidence is not itself audited. Without GuardDuty, there is no automated detection of IAM credential exfiltration or unusual API call patterns from task role credentials.

**Fix:**

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

### MEDIUM — kube-proxy Container Writes KUBECONFIG_DATA Env Var to /tmp in Plaintext

**File:** `deploy/regional/ecs.tf:148–151`

**Description:** The kube-proxy sidecar container command at line 150 is:

```
printf '%s' "$KUBECONFIG_DATA" > /tmp/kubeconfig && exec oc proxy ...
```

The `KUBECONFIG_DATA` environment variable holds a cluster kubeconfig (cluster credentials, API server URL, client certificates). It is written to `/tmp/kubeconfig` in plaintext inside the ephemeral container filesystem. The `/tmp` directory is provided via an ephemeral bind mount (`proxy-tmp` volume). The ECS task definition configuration means `KUBECONFIG_DATA` is expected to be injected via the `secrets` section from Secrets Manager — but the Terraform task definition definition does not show a `secrets` block for `KUBECONFIG_DATA` on the kube-proxy container. If `KUBECONFIG_DATA` is passed as an environment variable (not a secret), it is visible in plaintext in the ECS `DescribeTaskDefinitions` output and in CloudWatch container logs.

**Impact:** If `KUBECONFIG_DATA` is passed as a plaintext environment variable rather than a Secrets Manager reference, any SRE with `ecs:DescribeTaskDefinition` (granted by `DescribeAndListECS`, see H3) can extract the full cluster kubeconfig from the task definition definition, gaining direct API access to the target ROSA cluster without going through the investigation workflow. Even if injected via Secrets Manager, the plaintext file at `/tmp/kubeconfig` inside the container is readable by any process in the `kube-proxy` container after startup.

**Fix:** Ensure `KUBECONFIG_DATA` is always injected via a `secrets` block referencing Secrets Manager, never as a plaintext environment variable. Add the secrets block to the kube-proxy container definition in the Terraform task definition:

```hcl
secrets = [
  {
    name      = "KUBECONFIG_DATA"
    valueFrom = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project}/clusters/${cluster_id}/kubeconfig"
  }
]
```

Additionally, the `/tmp/kubeconfig` file should be removed immediately after `oc proxy` is started:

```sh
printf '%s' "$KUBECONFIG_DATA" > /tmp/kubeconfig && chmod 600 /tmp/kubeconfig
exec oc proxy ...
# Note: the exec replaces the shell, so cleanup after exec is not possible.
# Use a wrapper that deletes the file after oc proxy starts:
```

Consider using `KUBECONFIG` environment variable pointing to a RAM-backed tmpfs or passing kubeconfig via stdin to `oc proxy` if that feature is supported.

---

## Non-Findings

The following areas were checked and confirmed to have adequate controls in place:

| Area | What Was Checked | Finding |
|---|---|---|
| EFS transit encryption | `transit_encryption = "ENABLED"` in ECS task definition EFS volume config (`ecs.tf:76`) | Correct — TLS enforced for all EFS mounts |
| ECS EFS IAM enforcement | `iam = "ENABLED"` in EFS authorization config (`ecs.tf:79`) | Correct — IAM authorization enforced per access point |
| S3 public access block | All four public access block settings enabled (`s3.tf:36–39`) | Correct — public access fully blocked |
| S3 Object Lock | COMPLIANCE mode with `var.retention_days` (default 90) (`s3.tf:22–25`) | Correct — WORM protection in place |
| S3 versioning | `status = "Enabled"` (`s3.tf:11–13`) | Correct — required for Object Lock |
| S3 replication safety | `audit_replication_account_id` precondition enforced (`s3.tf:67–70`) | Correct — prevents replication without destination account ID |
| KMS key rotation | `enable_key_rotation = true` (`kms.tf:5`) | Correct — automatic annual rotation enabled |
| ECS Cluster Insights | `containerInsights = "enabled"` (`ecs.tf:6–8`) | Correct — container monitoring enabled |
| ECS Exec KMS | `kms_key_id = aws_kms_key.exec_session.arn` on cluster config (`ecs.tf:12`) | Correct — ECS Exec sessions are KMS-encrypted |
| EFS NFS ingress scope | EFS SG ingress restricted to Fargate SG only (`efs.tf:22–28`) | Correct — NFS port not exposed to VPC broadly |
| Fargate SG ingress | No ingress rules on Fargate SG (`ecs.tf:42–58`) | Correct — all inbound blocked, egress-only for ECR pull and SSM |
| Lambda invoker role scope | `lambda:InvokeFunction` on one specific Lambda ARN (`lambda-invoker.tf:77–83`) | Correct — minimal invoke scope |
| Reaper task scope | `ecs:DescribeTasks` and `ecs:StopTask` scoped to cluster task ARN prefix (`lambda-reap-tasks.tf:56–73`) | Correct — cluster-scoped |
| Reaper `ListTasks` condition | `StringEquals: ecs:cluster = cluster.arn` condition present (`lambda-reap-tasks.tf:47–53`) | Correct — conditioned on specific cluster |
| ECS Exec ssmmessages scope | `Resource = "*"` required by AWS for SSM channels; no known narrowing possible | Acceptable — AWS-required pattern |
| `iam:PassRole` scope | Scoped to task and execution role ARNs only (`lambda-create-investigation.tf:58–63`) | Correct — least privilege |
| S3 replication IAM | Replication policy scoped to source bucket and destination ARN only (`iam.tf:26–58`) | Correct — appropriately scoped |
| Terraform version constraint | `required_version = ">= 1.5"` — broad but provider lock file handles drift (see L5) | Existing finding L5 covers this |
| ECS `initProcessEnabled` | `initProcessEnabled = true` set on both containers | Correct — allows signal propagation for graceful shutdown |
| Keycloak OIDC audience check | Trust policies condition on `aud` claim (`oidc.tf:103–106`) | Correct — audience validated by STS |
| Multi-OIDC provider support | Separate provider resources with precondition validation (`oidc.tf:19–64`) | Correct — preconditions prevent partial configuration |
| `ssm_sessions` log retention | Uses `var.retention_days` (90 days default), separate from the 7-day `log_retention_days` (`ecs.tf:36`) | Correct — session logs have longer retention than operational logs |

---

## Summary of Top Findings by Severity

| ID | Severity | Title | File |
|---|---|---|---|
| C1 | Critical | Task role S3 GetObject unrestricted — cross-user audit read | `iam.tf:124` |
| H1 | High | No CloudTrail or GuardDuty | `main.tf:1` |
| H2 | High | Lambda not in VPC | `lambda-create-investigation.tf:114` |
| H3 | High | ABAC bypass via unrestricted DescribeAndListECS | `oidc.tf:201` |
| H5 | High | task_timeout=0 disables reaper enforcement | `lambda-reap-tasks.tf:63` |
| H7 | High | Group membership only enforced at app layer | `oidc.tf:88`, `lambda-invoker.tf:13` |
| H8 | High | SSM StartSession no ownership condition | `oidc.tf:212` |
| H9 | High | KMS key policy ECS principal lacks SourceArn | `kms.tf:36` |
| M1 | Medium | Lambda ECS wildcard resource | `lambda-create-investigation.tf:44` |
| M2 | Medium | SRE role KMS decrypt on all keys | `oidc.tf:222` |
| M3 | Medium | CloudWatch encryption disabled | `ecs.tf:17` |
| M4 | Medium | S3 uses SSE-S3 not SSE-KMS | `s3.tf:47` |
| M5 | Medium | No EFS filesystem policy | `efs.tf:1` |
| M6 | Medium | No S3 deny-non-TLS policy | `s3.tf:1` |
| M7 | Medium | Lambda CORS wildcard origins | `lambda-create-investigation.tf:167` |
| M10 | Medium | Bedrock all regions/models | `iam.tf:155` |
| M11 | Medium | No confused deputy conditions | `iam.tf:106`, `lambda-create-investigation.tf:12` |
| M12 | Medium | Missing DeleteAccessPoint permission | `lambda-create-investigation.tf:70` |
| M13 | Medium | Task role PutObjectAcl unnecessary | `iam.tf:131` |
| M14 | Medium | EFS uses AWS-managed key | `efs.tf:2` |
| M16 | Medium | KMS deletion window 7 days | `kms.tf:4` |
| NEW | Medium | kube-proxy KUBECONFIG_DATA plaintext env var | `ecs.tf:150` |
| NEW | Low | Execution role secrets wildcard covers all project secrets | `iam.tf:99` |
| NEW | Low | No S3 server access logging | `s3.tf:1` |
| NEW | Low | S3 lifecycle missing noncurrent version expiration | `s3.tf:102` |
| NEW | Low | KMS no admin/user separation | `kms.tf:10` |
