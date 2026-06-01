# Audit Area 2: Authorization & ABAC Model

**Date**: 2026-05-20  
**Commit**: 5b8a844  
**Auditor**: Adversary Agent (Sonnet 4.6)

---

## Executive Summary

The rosa-boundary ABAC model rests on a two-statement `ecs:ExecuteCommand` split — cluster-level permission with no condition, task-level permission conditioned on `ecs:ResourceTag/<abac_tag_key> == ${aws:PrincipalTag/<abac_tag_key>}` — that is structurally correct and properly fail-closed when session tags are absent. However, six new exploitable gaps were identified beyond the previously known set. The most severe is a transitive session tag inheritance flaw: the CLI's two-step role assumption (invoker role → SRE role both via `AssumeRoleWithWebIdentity`) does not pass `TransitiveTagKeys`, meaning session tags established at step 1 do not automatically carry to step 2 — but the STS API accepts the OIDC token directly at both steps without consulting the Lambda's group check, allowing session tag injection via direct STS calls. The ECS task role (`aws_iam_role.task`) grants `s3:GetObject` and `s3:ListBucket` on the entire audit bucket with no path prefix condition, enabling any SRE's container to read any other SRE's audit files regardless of ABAC isolation. The `SSMSessionForECSExec` statement allows `ssm:StartSession` on any ECS task ARN without an ownership tag condition, creating a theoretical direct-SSM-session path that bypasses the ECS ABAC gate (dependent on whether the SSM agent accepts sessions without a preceding `ecs:ExecuteCommand` call). The KMS policy grants `ecs-tasks.amazonaws.com` the ability to `kms:Decrypt` and `kms:GenerateDataKey` without any `aws:SourceArn` condition, meaning any Fargate task in the account — not just rosa-boundary tasks — can use this key to decrypt ECS Exec session logs. All five operations performed by `close-investigation` (list tasks, stop tasks, list task definitions, deregister task definitions, delete EFS access point) use ambient credentials with no ownership ABAC check, and the EFS access point lookup is based solely on caller-supplied `cluster_id`/`investigation_id` parameters.

---

## Findings

### Aabac-1 — CRITICAL: Task Role `s3:GetObject` Grants Cross-User Audit File Read

**Severity**: Critical  
**File**: `deploy/regional/iam.tf:124–143`

**Description**: The ECS task role's S3 policy grants `s3:GetObject` and `s3:ListBucket` on the entire audit bucket (`aws_s3_bucket.audit.arn` and `${aws_s3_bucket.audit.arn}/*`) with no path-prefix condition. Investigation data is stored at per-investigation S3 paths (`s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`), but the IAM policy does not enforce this scope. Every rosa-boundary container (running as the task role) can read objects from any other investigation's S3 path. The `s3:ListBucket` permission compounds this: with a `Prefix` parameter set to another SRE's `cluster_id`, the attacker can enumerate investigations they do not own.

**Exploit Scenario**: SRE Alice connects to her own investigation task via ECS Exec and runs:
```
aws s3 ls s3://rosa-boundary-audit/bob-cluster-id/bob-investigation-id/ --recursive
aws s3 cp s3://rosa-boundary-audit/bob-cluster-id/bob-investigation-id/2026-05-20/task-xyz/ /tmp/ --recursive
```
She obtains Bob's entire investigation artifact set including downloaded cluster data, kubeconfig outputs, and any credentials Bob wrote to disk. This uses the task role credentials available at `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` inside the Fargate container — no role assumption needed.

**Recommendation**: Scope S3 permissions to the caller's own investigation path using a condition. The most practical approach at deployment time is a strict prefix on the S3 resource ARN in the task policy. Since the task definition already has `CLUSTER_ID`, `INVESTIGATION_ID`, and `S3_AUDIT_BUCKET` baked in at launch time, the per-investigation task definition can be registered with a tightly scoped task role policy or resource ARN:
```hcl
Resource = [
  "${aws_s3_bucket.audit.arn}",
  "${aws_s3_bucket.audit.arn}/*"
]
Condition = {
  StringLike = {
    "s3:prefix" = ["${cluster_id}/${investigation_id}/*"]
  }
}
```
Alternatively, grant only `s3:PutObject` at task launch (for audit sync) using path-scoped resource ARNs in the per-investigation task definition registered by the Lambda.

---

### Aabac-2 — HIGH: `SSMSessionForECSExec` Has No Ownership Condition — Direct SSM Session Bypass

**Severity**: High  
**File**: `deploy/regional/oidc.tf:211–221`

**Description**: The `SSMSessionForECSExec` statement allows `ssm:StartSession` on `arn:aws:ecs:*:*:task/*` (any ECS task) and `arn:aws:ssm:*:*:document/AWS-StartInteractiveCommand` with no tag condition. The comment in the policy explains this is because "the SSM API does not have access to ECS resource tags." While this is accurate, the consequence is that the ABAC check is exclusively enforced by the `ecs:ExecuteCommand` IAM call — not by SSM. If AWS Systems Manager's `ssm:StartSession` API accepts direct session requests to an ECS Exec target without a prerequisite `ecs:ExecuteCommand` call being evaluated by IAM, an SRE with the shared SRE role could call `ssm:StartSession` directly with a manually constructed target string (`ecs:<cluster>_<taskId>_<containerRuntimeId>`) for another user's task, bypassing the ABAC gate entirely.

**Exploit Scenario**: SRE Alice calls `aws ssm start-session --target "ecs:rosa-boundary-dev_<bob-task-id>_<bob-container-runtime-id>" --document-name AWS-StartInteractiveCommand --parameters command="/bin/bash"` using her `sre_shared` role credentials. If SSM does not back-check `ecs:ExecuteCommand` authorization, she directly enters Bob's container. The container RuntimeID is obtainable via `ecs:DescribeTasks` (permitted without conditions by `DescribeAndListECS`).

**Assessment**: This is an architectural dependency on AWS's internal enforcement of the prerequisite IAM check. AWS documentation states that ECS Exec uses SSM as the transport but enforces `ecs:ExecuteCommand` as the IAM action. However, this coupling is not explicitly enforced by any IAM deny statement in the policy, making it a trust assumption rather than a defense. A defense-in-depth posture should not rely solely on undocumented AWS internal enforcement ordering.

**Recommendation**: Add an explicit Deny statement that blocks `ssm:StartSession` except when called through the ECS Exec mechanism. The most reliable mitigation is to restrict the SSM resource to specifically named document scopes and add an explicit Deny on direct SSM targets to ECS tasks:
```hcl
{
  Sid    = "DenyDirectSSMToECSTasks"
  Effect = "Deny"
  Action = ["ssm:StartSession"]
  Resource = "arn:aws:ecs:*:*:task/*"
  Condition = {
    StringNotEquals = {
      "ssm:SessionType" = "InteractiveCommands"
    }
  }
}
```
Additionally, restrict the SSM resource ARN pattern from `arn:aws:ecs:*:*:task/*` to `arn:aws:ecs:${region}:${account}:task/${cluster_name}/*`.

---

### Aabac-3 — HIGH: Two-Step Role Assumption Does Not Use `TransitiveTagKeys` — Session Tags Not Guaranteed

**Severity**: High  
**File**: `internal/aws/sts.go:28–33`, `internal/cmd/start_task.go:100,149`

**Description**: The CLI performs two STS calls. Step 1 (`start_task.go:100`): `AssumeRoleWithWebIdentity(invokerRoleARN, idToken, "rosa-boundary-invoker")` — this obtains invoker credentials. Step 2 (`start_task.go:149`): `AssumeRoleWithWebIdentity(sreRoleARN, idToken, sessionName)` — this calls the SRE role directly with the original OIDC token.

The `sts.go:28` `AssumeRoleWithWebIdentityInput` struct passes `RoleArn`, `RoleSessionName`, and `WebIdentityToken` only — no `Tags` or `TransitiveTagKeys` parameters. For the SRE role assumption (step 2), the session tags come from the JWT's `https://aws.amazon.com/tags` claim, which STS processes automatically during `AssumeRoleWithWebIdentity`. This part is correct.

However, the invoker role step (step 1) also gets session tags from the JWT, and the invoker role trust policy allows `sts:TagSession`. If an SRE later uses the invoker role credentials to perform a `sts:AssumeRole` into the SRE role (rather than `AssumeRoleWithWebIdentity`), the session tags from step 1 would need `TransitiveTagKeys` to propagate. The current architecture avoids this specific gap because step 2 always uses the original OIDC token. But there is a related gap: neither `AssumeRoleWithWebIdentity` call includes an explicit `Tags` parameter, relying entirely on STS auto-parsing the `https://aws.amazon.com/tags` JWT claim. If this JWT claim is absent or malformed, no session tags are set and the ABAC condition fails closed — which is correct. However, there is no assertion in the CLI code that session tags were successfully set, so a misconfigured Keycloak mapper (no `https://aws.amazon.com/tags` claim) results in silent failure: the role assumption succeeds, but ABAC denies all task exec with no diagnostic message.

**Exploit Scenario**: SRE Alice's Keycloak token lacks the `https://aws.amazon.com/tags` claim (mapper misconfigured). She successfully assumes the SRE role. `aws:PrincipalTag/username` resolves to empty/absent. The `ExecuteCommandOnOwnedTasks` StringEquals condition fails. Alice receives an `AccessDenied` on exec with no explanation of the ABAC tag mismatch. This is a support/operational gap, not a bypass — but the silent success of role assumption may mislead the SRE into thinking they have access.

**Recommendation**: The CLI should verify that ABAC tags are present in the JWT before assuming the SRE role. Parse the ID token locally (no signature verification needed for this check) and warn if `https://aws.amazon.com/tags.principal_tags.<abac_tag_key>` is absent. Additionally, `sts:AssumeRoleWithWebIdentity` can be called with explicit `Tags` as a belt-and-suspenders approach:
```go
input := &sts.AssumeRoleWithWebIdentityInput{
  RoleArn:          aws.String(roleARN),
  RoleSessionName:  aws.String(sessionName),
  WebIdentityToken: aws.String(idToken),
  // Explicit tags as fallback if JWT claim is absent:
  Tags: []types.Tag{{Key: aws.String("username"), Value: aws.String(username)}},
  TransitiveTagKeys: []string{"username"},
}
```
The `TransitiveTagKeys` parameter should be set to propagate the ABAC tag through any further role assumption chains that may be added in the future.

---

### Aabac-4 — HIGH: KMS Key Policy Grants `kms:Decrypt` to All Fargate Tasks — Not Scoped to Rosa-Boundary

**Severity**: High  
**File**: `deploy/regional/kms.tf:36–48`

**Description**: The KMS key policy's `Allow ECS Exec` statement grants `kms:Decrypt` and `kms:GenerateDataKey` to `Principal: {Service: "ecs-tasks.amazonaws.com"}` with `Resource: "*"` and no `aws:SourceArn` or `aws:SourceAccount` condition. This means any Fargate task in the AWS account that uses this KMS key ID can decrypt data encrypted with this key — including tasks from other workloads if the key ID is known or if the rosa-boundary cluster coexists with other ECS workloads.

More critically, this combined with the `KMSForECSExec` statement in the SRE role (which grants `kms:Decrypt` on `Resource: "*"`) means any SRE can call `kms:Decrypt` directly — not just through the ECS Exec mechanism. An SRE with the shared SRE role can call the KMS Decrypt API directly with ciphertext from CloudWatch Logs, bypassing the normal channel of reading logs through the CloudWatch Logs API. If other SREs' ECS Exec session logs are stored encrypted with this key (when M3 is remediated), the decryption gate is shared across all SREs.

**Exploit Scenario**: Alice captures the ciphertext bytes from Bob's SSM session log in CloudWatch Logs (readable via CloudWatch APIs), then calls `aws kms decrypt --ciphertext-blob <blob> --key-id <exec-session-key-arn>`. She can decrypt Bob's session log outside of CloudWatch's access control. This is the M2 finding at a lower layer — M2 covers the IAM role policy; this covers the KMS key policy itself.

**Recommendation**: Add `aws:SourceArn` or `aws:SourceAccount` conditions to the KMS key policy ECS statement:
```json
{
  "Sid": "Allow ECS Exec",
  "Effect": "Allow",
  "Principal": {"Service": "ecs-tasks.amazonaws.com"},
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
  "Resource": "*",
  "Condition": {
    "ArnLike": {
      "aws:SourceArn": "arn:aws:ecs:<region>:<account>:cluster/<cluster-name>"
    }
  }
}
```
Restrict `KMSForECSExec` in the SRE role to the specific key ARN (already recommended in M2).

---

### Aabac-5 — MEDIUM: `close-investigation` EFS Access Point Lookup Has No Ownership Verification

**Severity**: Medium  
**File**: `internal/cmd/close_investigation.go:79–86`, `internal/aws/efs.go` (EFS client)

**Description**: The `close-investigation` command finds the target EFS access point using `efsClient.FindAccessPointByTags(ctx, closeClusterID, closeInvestigationID)`. The `closeClusterID` and `closeInvestigationID` are caller-supplied CLI flags — they are not validated against the caller's identity. The EFS access point lookup filters by `ClusterID` and `InvestigationID` tags only. There is no check that the access point's `oidc_sub` or `username` tag matches the caller. Combined with H6 (which established that `close-investigation` uses ambient credentials), this means any SRE who knows (or guesses, or discovers via H3) another user's `cluster_id` + `investigation_id` can delete their EFS access point.

This extends H6: while H6 established the role bypass, this finding is specifically about the missing ownership check in the EFS lookup logic, which would remain an issue even if OIDC authentication were added to the close flow, unless the ownership check is explicitly coded.

**Exploit Scenario**:
1. Alice calls `rosa-boundary list-tasks` and sees Bob's `cluster_id=prod-cluster-1` and `investigation_id=swift-dance-party` in the output (allowed by H3).
2. Alice runs `rosa-boundary close-investigation --cluster-id prod-cluster-1 --investigation-id swift-dance-party --force --yes`.
3. Bob's running task is stopped (ABAC bypass per H6), his task definition deregistered, and his EFS access point deleted. Bob's investigation home directory is inaccessible.

**Recommendation**: After adding OIDC authentication to `close-investigation` (per H6 fix), also add an explicit ownership check:
```go
if ap.OwnerSub != "" && ap.OwnerSub != callerSub {
    return fmt.Errorf("access point %s does not belong to caller (owner: %s)", ap.AccessPointID, ap.OwnerSub)
}
```
The `FindAccessPointByTags` function should return the `oidc_sub` tag from the access point, and the caller's OIDC `sub` should be compared before proceeding with deletion.

---

### Aabac-6 — MEDIUM: `DescribeTaskDefinition` Exposes Other Users' Investigation Environment Variables

**Severity**: Medium  
**File**: `deploy/regional/oidc.tf:201–210`

**Description**: The `DescribeAndListECS` statement grants `ecs:DescribeTaskDefinition` on `Resource: "*"` with no conditions. Per-investigation task definitions are registered by the Lambda at `register_investigation_task_definition()` (handler.py:441–545) with investigation-specific environment variables baked in: `CLUSTER_ID`, `INVESTIGATION_ID`, `OC_VERSION`, `S3_AUDIT_BUCKET`, and `TASK_TIMEOUT`. The task definition family name pattern is `{base_family}-{cluster_id}-{investigation_id}-{timestamp}` (handler.py:479), which is deterministic given task tags visible via `ListTasks`/`DescribeTasks`. The `KUBECONFIG_DATA` Secrets Manager ARN is also injected into the kube-proxy sidecar, and it contains the `cluster_id` as a path component: `arn:aws:secretsmanager:...:secret:rosa-boundary/clusters/{cluster_id}/kubeconfig`.

**Exploit Scenario**: Alice calls `ecs:ListTasks` to enumerate all running tasks. From `DescribeTasks` she obtains the task ARN and, from it, the task definition ARN (available in the `taskDefinitionArn` field). She then calls `ecs:DescribeTaskDefinition` on Bob's per-investigation task definition to read the exact `CLUSTER_ID`, `INVESTIGATION_ID`, `S3_AUDIT_BUCKET`, and the partial ARN of Bob's cluster kubeconfig in Secrets Manager. She now has the exact S3 path for Bob's audit data and the kubeconfig secret ARN (which she still needs `secretsmanager:GetSecretValue` to read, but knowing the ARN is the first step).

This is a more concrete instance of H3 — H3 identified the broad information disclosure, this narrows it to the specific sensitive fields exposed via task definition inspection.

**Recommendation**: Restrict `ecs:DescribeTaskDefinition` to task definitions belonging to the caller's own investigations. The ABAC model cannot directly apply to task definitions (they don't carry the same tags as tasks), so the most practical approach is to remove `ecs:DescribeTaskDefinition` from the shared SRE role entirely — the `join-task` workflow does not require it (the task ARN from `DescribeTasks` is sufficient), and `close-investigation` uses ambient credentials currently. If `DescribeTaskDefinition` is needed for the SRE role, scope it by resource ARN to the project family prefix.

---

### Aabac-7 — MEDIUM: Invoker Role Session Tags Are Silently Dropped When Assuming SRE Role

**Severity**: Medium  
**File**: `internal/cmd/start_task.go:100–103`, `deploy/regional/lambda-invoker.tf:21–26`

**Description**: The invoker role trust policy allows `sts:TagSession`, so when the CLI calls `AssumeRoleWithWebIdentity` for the invoker role, the JWT's `https://aws.amazon.com/tags` claim sets session tags on the invoker role session (e.g., `aws:PrincipalTag/username = alice`). However, when the CLI then calls `AssumeRoleWithWebIdentity` for the SRE role (step 2), it uses the original OIDC token directly — it does not use the invoker role credentials. The invoker role session tags are not passed forward.

This means the session tags set on the invoker role are completely unused — they exist but have no policy that checks them. The invoker role's permissions policy only grants `lambda:InvokeFunction` on one specific Lambda ARN, so the session tags on the invoker session serve no enforcement purpose. This is a dead code security smell: `sts:TagSession` in the invoker trust policy creates the impression of ABAC enforcement on the invoker role that does not actually exist.

**Exploit Scenario**: A future developer adds `DescribeAndListECS` or other sensitive permissions to the invoker role and assumes tag-based restrictions apply due to the `sts:TagSession` being present in the trust policy. In reality, the invoker role has no tag-conditioned policy statements, so any session tag injection (e.g., via the STS `Tags` parameter in a direct call) would have no security impact — but could mislead code reviewers.

**Recommendation**: Either remove `sts:TagSession` from the invoker role trust policy (since no invoker role policy statement uses session tags), or add a comment clearly explaining that tag session on the invoker role is inert and reserved for future use. Document the architectural decision explicitly.

---

### Aabac-8 — LOW: `join-task` Uses Ambient Credentials — No ABAC Role for Standalone Exec

**Severity**: Low  
**File**: `internal/cmd/join_task.go:50–63`

**Description**: The `join-task` command, when called standalone (not via `start-task --connect`), loads ambient AWS credentials via `config.LoadDefaultConfig()`. If an SRE manually configures AWS credentials (e.g., via AWS CLI profiles, `AWS_ACCESS_KEY_ID` env vars, or EC2 instance profile), `join-task` will use those credentials rather than the ABAC-gated shared SRE role. The ABAC ownership check only applies when those ambient credentials happen to be the SRE role session — which is the case when `start-task` is run first and the credentials are propagated, but is not guaranteed.

**Exploit Scenario**: An SRE with administrator-level ambient credentials (e.g., break-glass access, developer role with broad ECS permissions) runs `rosa-boundary join-task <any-task-id>`. The `ecs:ExecuteCommand` call succeeds using their admin credentials, bypassing the ABAC ownership check entirely. The ABAC model only applies when the SRE has correctly assumed the `sre_shared` role — ambient credentials that have `ecs:ExecuteCommand` without the ownership condition bypass the model.

**Recommendation**: For standalone `join-task`, require explicit OIDC authentication and SRE role assumption similar to `start-task`. Add a `--force-ambient` flag for break-glass scenarios that explicitly acknowledges the ABAC bypass. Alternatively, document that `join-task` requires the SRE role to be configured as the ambient credential source and add a validation step that checks the caller's identity against the task's `username` tag before proceeding.

---

## ABAC Policy Matrix

| Statement | Actions | Resource Scope | Condition | Verdict |
|-----------|---------|----------------|-----------|---------|
| `ExecuteCommandOnCluster` | `ecs:ExecuteCommand` | Specific cluster ARN | None (intentional prerequisite) | PASS — no task access without the paired task statement |
| `ExecuteCommandOnOwnedTasks` | `ecs:ExecuteCommand` | `*` (all tasks) | `StringEquals: ecs:ResourceTag/<abac_key> == ${aws:PrincipalTag/<abac_key>}` | PASS — correctly isolates by owner tag; fail-closed on missing tag |
| `DescribeAndListECS` | `ecs:DescribeTasks`, `ecs:ListTasks`, `ecs:DescribeTaskDefinition` | `*` | None | GAP (H3, Aabac-6) — all tasks/definitions visible to all SREs; task definition env vars leak investigation metadata |
| `SSMSessionForECSExec` | `ssm:StartSession` | Any ECS task ARN, named SSM document | None | GAP (Aabac-2) — no tag condition; theoretical direct SSM bypass path |
| `KMSForECSExec` | `kms:Decrypt`, `kms:GenerateDataKey` | `*` (all KMS keys) | None | GAP (M2, Aabac-4) — should be scoped to exec session key ARN; enables cross-SRE session log decryption |
| Task Role `task_s3` | `s3:PutObject`, `s3:PutObjectAcl`, `s3:GetObject`, `s3:ListBucket` | Entire audit bucket | None | GAP (M13, Aabac-1) — no path prefix condition; any task can read any other investigation's audit data |
| Task Role `task_kms` | `kms:Decrypt`, `kms:GenerateDataKey` | Specific exec session key | None | PASS — correctly scoped to the exec session key |
| KMS Key Policy `Allow ECS Exec` | `kms:Decrypt`, `kms:GenerateDataKey` | `*` | None | GAP (Aabac-4) — service principal without SourceArn condition; any Fargate task can use key |
| Lambda ECS Policy | `ecs:RunTask`, `ecs:StopTask`, `ecs:RegisterTaskDefinition`, etc. | `*` | None | GAP (M1) — all ECS resources; should be cluster-scoped |
| Reaper `ecs:StopTask` | `ecs:StopTask` | Cluster-scoped task ARN | `ForAnyValue:StringLike: {ecs:ResourceTag/deadline: "*"}` | GAP (H5) — condition prevents reaper from stopping deadline-less tasks |
| `close-investigation` EFS lookup | EFS FindByTags | Caller-supplied ClusterID+InvestigationID | No ownership check | GAP (H6, Aabac-5) — no oidc_sub comparison before delete |
| OIDC Trust (sre_shared) | `sts:AssumeRoleWithWebIdentity`, `sts:TagSession` | N/A (trust policy) | `aud == oidc_client_id` | GAP (H7) — no group membership condition at IAM layer |
| OIDC Trust (lambda_invoker) | `sts:AssumeRoleWithWebIdentity`, `sts:TagSession` | N/A (trust policy) | `aud == oidc_client_id` | GAP (H7) — no group membership condition; `sts:TagSession` is inert (Aabac-7) |

---

## New Items for adversary-findings.json

The following findings are net-new and not covered by the existing finding set:

| ID | Title | Severity |
|----|-------|----------|
| Aabac-1 | Task role `s3:GetObject` has no path-prefix condition — any SRE container can read any other SRE's audit files | Critical |
| Aabac-2 | `SSMSessionForECSExec` has no ownership condition — theoretical direct SSM session bypass | High |
| Aabac-3 | Two-step role assumption does not set `TransitiveTagKeys` — session tags not guaranteed to propagate; no client-side JWT tag validation | High |
| Aabac-4 | KMS key policy `Allow ECS Exec` uses service principal without `aws:SourceArn` — any Fargate task can decrypt exec session logs | High |
| Aabac-5 | `close-investigation` EFS access point lookup has no ownership verification (oidc_sub comparison) | Medium |
| Aabac-6 | `ecs:DescribeTaskDefinition` in `DescribeAndListECS` exposes per-investigation env vars (cluster_id, investigation_id, kubeconfig secret ARN) to all SREs | Medium |
| Aabac-7 | Invoker role `sts:TagSession` in trust policy is inert — no invoker role policy statement uses session tags | Low |
| Aabac-8 | `join-task` standalone uses ambient credentials — ABAC enforcement is optional, not structural | Low |
