# rosa-boundary Security Assessment

> Generated: 2026-05-18  
> Scope: Full repository audit — IAM, IaC, container supply chain, runtime controls  
> Standard: AWS Well-Architected Framework (Security Pillar), FedRAMP High, CIS AWS Foundations Benchmark

---

## Section 1: Component & Dependency Inventory

### Go CLI (`go.mod`)

| Module | Version | Status |
|--------|---------|--------|
| `aws-sdk-go-v2` | v1.41.2 | Current |
| `spf13/cobra` | v1.10.2 | Current |
| `spf13/viper` | v1.21.0 | Current |
| `golang.org/x/text` | v0.28.0 | No known CVEs |
| Go toolchain | 1.24.4 | Current |

`go.sum` committed and complete. No known vulnerable Go modules identified.

### Python Lambda Dependencies

| Package | Specifier | Notes |
|---------|-----------|-------|
| `PyJWT` | `>=2.8.0` | Locked via uv.lock w/ hashes |
| `cryptography` | `>=41.0.0` | Locked via uv.lock |
| `requests` | `>=2.31.0` | Locked via uv.lock |
| `boto3` | `>=1.34.0` | 1.42.57 in lock |

**Risk**: `pyproject.toml` uses `>=` specifiers (finding M9). The reap-tasks Lambda has no dependencies beyond stdlib + boto3 (runtime-provided).

### Container (`Containerfile`)

| Component | Notes |
|-----------|-------|
| Base: `fedora:43` | Tag-pinned, no digest (finding L6) |
| Official AWS CLI v2 | Fetched at build time via `awscli.amazonaws.com` — no integrity check |
| OpenShift CLI v4.14–4.20 | Fetched from Red Hat mirror — no checksum verification |
| Claude Code | Installed via `curl \| bash` from `claude.ai/install.sh` (finding L7) |

### Infrastructure as Code

| File | Purpose |
|------|---------|
| `deploy/regional/*.tf` | Full AWS deployment: ECS, Lambda, EFS, KMS, S3, IAM, OIDC, EventBridge |
| `deploy/keycloak/` | Kustomize — Keycloak RHBK on OpenShift w/ CloudNativePG |

Terraform version requirement `>= 1.5`, AWS provider `~> 5.0`. The `.terraform.lock.hcl` is gitignored (finding L5).

---

## Section 2: Internal Access Controls & Least Privilege

### Hardcoded Credentials

**None found.** All credentials derive from OIDC token exchange or STS. `.env.example` contains only placeholders and is gitignored.

### IAM Role Scoping Summary

| Role | Concern |
|------|---------|
| `task-role` | `s3:PutObjectAcl` unnecessary (M13); `bedrock:*` all regions (M10); `ssmmessages:*` on `*` (no resource-level support — acceptable) |
| `execution-role` | Secretsmanager access scoped to `${project}/*` — acceptable |
| `create-investigation-lambda` | ECS actions on `Resource = "*"` (M1); missing `DeleteAccessPoint` permission for cleanup paths (M12) |
| `reap-tasks-lambda` | Well-scoped — cluster-conditioned ListTasks, ARN-scoped DescribeTasks/StopTask |
| `sre_shared` | KMS Decrypt on `*` (M2); DescribeAndListECS leaks other users' task metadata (H3) |
| `lambda_invoker` | Narrow — only `lambda:InvokeFunction` on specific ARN. Excellent. |

### GitHub Actions Workflow Permissions

- `upload-sarif.yml`: explicit `security-events: write, contents: read` — correct and minimal.
- **`localstack-tests.yml`: no `permissions:` block** — falls back to repository default, which may be `contents: write`.

### OWNERS / Branch Protection

`OWNERS` file with 3 approvers (Prow-based). No `CODEOWNERS` file — GitHub-native branch protection may not enforce Prow approvers.

---

## Section 3: External Access Controls & AWS IAM Mechanics

### External Integrations

| Integration | Auth | Risk |
|-------------|------|------|
| Keycloak OIDC | JWKS signature validation + `aud`/`iss` checks | Low |
| GitHub Actions | `LOCALSTACK_AUTH_TOKEN` in repo secrets | Low |
| Amazon Bedrock | Task role SigV4 | Medium (M10 — all regions/models) |
| ECS Exec | KMS-encrypted SSM channel | Low |

### OIDC Token Validation

The `validate_oidc_token()` function correctly checks signature (RS256), `exp`, and `aud`. Concerns:

- `PyJWKClient` instantiated per-request — cold starts hit Keycloak's JWKS endpoint over the public internet on every new Lambda execution environment (H2).
- No certificate pinning on JWKS fetch — DNS hijack would allow JWKS substitution.
- No explicit `nbf` check beyond PyJWT defaults.

### IAM Trust Relationships

All OIDC trust policies use `StringEquals` on `<issuer>:aud` — correct. However:

- No `<issuer>:sub` constraint — any Keycloak-authenticated user can assume the roles; authorization is delegated to the Lambda and ABAC layer.
- ECS task, execution, and Lambda roles lack **confused deputy protection** (`aws:SourceAccount`/`aws:SourceArn` on service principal trust) — finding M11.

### KMS Key Policy

The ECS exec session key has a 7-day deletion window. **FedRAMP/NIST recommends 30 days minimum** for keys protecting audit evidence (SC-28).

### Permissions Boundaries

**None defined anywhere in the Terraform.** FedRAMP AC-6(1) calls for permissions boundaries to prevent privilege escalation if a role is compromised.

### Explicit Deny Statements

**None found.** For FedRAMP, explicit Denies are recommended for:

- Actions outside authorized AWS regions (data residency enforcement)
- Privilege escalation paths on task/execution roles
- Non-TLS S3 access (finding M6)

---

## Section 4: Risk Assessment & Remediation Matrix

### Critical

None identified.

---

### High

| ID | Description | Standard Violated | Remediation |
|----|-------------|-------------------|-------------|
| **H1** | No CloudTrail or GuardDuty in Terraform scope — API calls to ECS, EFS, KMS, Lambda, and S3 data events produce no audit record | FedRAMP AU-2, AU-3, AU-12; CIS AWS 3.1–3.7 | Add `aws_cloudtrail` with S3 data events enabled; add `aws_guardduty_detector` to deployment |
| **H2** | Lambda not deployed inside VPC — JWKS fetching and all AWS API calls traverse the public internet | FedRAMP SC-7; Well-Architected Security Pillar | Add `vpc_config` to both Lambda functions; deploy VPC Interface Endpoints for ECS, EFS, STS, Secrets Manager, Lambda |
| **H3** | `DescribeAndListECS` on the shared SRE role allows any SRE to enumerate all tasks and task definitions, leaking other users' investigation metadata | FedRAMP AC-3, AC-6; data minimization | Scope `ecs:DescribeTasks` to cluster ARN; add ABAC condition `ecs:ResourceTag/username == ${aws:PrincipalTag/username}` on Describe; restrict `ListTaskDefinitions` to family prefix |

---

### Medium

| ID | Description | Standard Violated | Remediation |
|----|-------------|-------------------|-------------|
| **M1** | create-investigation Lambda uses `Resource = "*"` for ECS RunTask, StopTask, TagResource | Well-Architected Security Pillar; FedRAMP AC-6 | Scope to cluster ARN: `arn:aws:ecs:${region}:${account}:cluster/${cluster_name}` and task family prefix |
| **M2** | Shared SRE role grants `kms:Decrypt` on `*` | FedRAMP AC-6; CIS AWS 1.16 | Scope to `aws_kms_key.exec_session.arn` |
| **M3** | CloudWatch log groups for ECS Exec / Lambda have no CMK encryption | FedRAMP SC-28; CIS AWS 3.7 | Enable `kms_key_id` on all `aws_cloudwatch_log_group` resources |
| **M4** | S3 audit bucket uses SSE-S3, not SSE-KMS with a CMK | FedRAMP SC-28 | Set `sse_algorithm = "aws:kms"` with a dedicated CMK; deny `s3:PutObject` without `s3:x-amz-server-side-encryption: aws:kms` |
| **M5** | No EFS filesystem policy — any principal with network access and basic EFS permissions can mount without using an access point | FedRAMP AC-3; Well-Architected Storage | Add `aws_efs_file_system_policy` with `Deny` for `!efs:AccessPointArn` condition |
| **M6** | No S3 bucket policy denying non-TLS requests | FedRAMP SC-8; CIS AWS 2.1.2 | Add bucket policy statement: `Effect: Deny`, `Condition: aws:SecureTransport = false` |
| **M7** | Lambda function URL CORS allows all origins (`"*"`) | OWASP API4; FedRAMP AC-17 | Restrict `allow_origins` to specific known origins or remove CORS if Lambda is only called by the CLI (which uses SigV4, not CORS) |
| **M8** | Container SRE user has `sudo ALL` (passwordless) in `/etc/sudoers.d/sre` | FedRAMP AC-6; container security | Restrict to `NOPASSWD: /usr/sbin/alternatives` only; `ALL` allows privilege escalation inside the container |
| **M9** | Python `pyproject.toml` uses `>=` version specifiers; uv.lock not verified in deployment pipeline | FedRAMP SA-12 Supply Chain | Pin to exact versions in pyproject.toml; add `uv lock --check` step to CI |
| **M10** | Bedrock IAM action `bedrock:*` spans all regions and all model ARNs | FedRAMP SC-7 (data residency); cost abuse | Scope to `arn:aws:bedrock:us-east-1::foundation-model/anthropic.*` |
| **M11** | ECS task/execution roles and Lambda execution roles lack confused deputy protection on service principal trust | AWS IAM Best Practices; FedRAMP AC-17 | Add `aws:SourceAccount` condition to service principal trust statements |
| **M12** | Lambda lacks `elasticfilesystem:DeleteAccessPoint` permission despite calling it in cleanup paths | FedRAMP SI-12; operational integrity | Grant `DeleteAccessPoint` in Lambda EFS policy; add cleanup error alerting |
| **M13** | Task role grants `s3:PutObjectAcl` on audit bucket — unnecessary | FedRAMP AC-6; CIS AWS | Remove `s3:PutObjectAcl`; only `PutObject`, `GetObject`, `ListBucket` are needed |
| **M14** | EFS filesystem encrypted with AWS-managed key, not a CMK | FedRAMP SC-28 (enhanced) | Add `kms_key_id` to `aws_efs_file_system` using a dedicated CMK |

---

### Low

| ID | Description | Standard Violated | Remediation |
|----|-------------|-------------------|-------------|
| **L1** | ~~XSS in OAuth callback error page~~ | — | **Resolved** — confirmed fixed in `callback.go` |
| **L2** | EFS security group permits all egress | Defense-in-depth | Remove the egress rule from the EFS security group |
| **L3** | Example lifecycle script uses `assignPublicIp=ENABLED` | Documentation risk | Change to `DISABLED`; add a warning comment explaining it requires NAT/endpoints |
| **L4** | `oc_version` parameter not validated in Lambda handler against an allowlist | FedRAMP SI-10 (Input Validation) | Validate against: `["4.14","4.15","4.16","4.17","4.18","4.19","4.20"]` |
| **L5** | `.terraform.lock.hcl` is gitignored; provider pinned only to `~> 5.0` | Supply chain integrity | Remove from `.gitignore`; commit the lock file |
| **L6** | Fedora base image pinned to tag, not digest | Container supply chain | Pin: `FROM fedora:43@sha256:<digest>` |
| **L7** | Claude Code installed via `curl \| bash` with no integrity verification | FedRAMP SA-12 | Verify installer SHA256 before execution; or pull from a pre-validated internal registry |
| **L8** | GitHub Actions pinned to mutable version tags, not commit SHAs | FedRAMP SA-12; supply chain | Pin all `uses:` to full commit SHAs; use Renovate/Dependabot for updates |
| **L9** | `uv` installed in CI via `curl \| sh` without integrity check | FedRAMP SA-12 | Replace with `astral-sh/setup-uv` action pinned to a commit SHA |
| **L10** | Default `log_retention_days = 7` — below FedRAMP AU-11 minimum | FedRAMP AU-11; CIS AWS 3.13 | Set default to 365; export to S3 Glacier with a 3-year lifecycle for full retention |

---

## Finding Summary

| Severity | Count | IDs |
|----------|-------|-----|
| Critical | 0 | — |
| High | 3 | H1, H2, H3 |
| Medium | 14 | M1–M14 |
| Low | 10 | L1–L10 |

---

## Notable Architecture Strengths

- **ABAC session-tagged shared role** — no per-user role sprawl; OIDC tags flow through STS correctly.
- **Reaper Lambda IAM** — the best-scoped policy in the deployment; cluster-conditioned ListTasks, ARN-scoped DescribeTasks/StopTask.
- **Lambda function URL authentication** — `authorization_type = "AWS_IAM"` provides SigV4 as a strong first auth layer before OIDC validation.
- **PKCE implementation** — `crypto/rand` for code verifier and state; state validated on callback (CSRF-protected).
- **S3 Object Lock COMPLIANCE mode** — strong WORM control for audit evidence.
- **ECS Exec KMS encryption** — transit encryption on all interactive sessions.
- **`iam:PassRole` correctly scoped** — limited to only the task and execution role ARNs.

---

## Recommended Remediation Priority

For a FedRAMP accreditation path, address in this order:

1. **H1** — No audit trail (CloudTrail + GuardDuty) — blocker for AU controls
2. **H2** — Lambda outside VPC — blocker for SC-7
3. **M5** — EFS filesystem policy (access-point enforcement)
4. **M3, M4, M14** — CMK encryption gaps (SC-28)
5. **H3** — Cross-user task enumeration (AC-3, AC-6)
6. **M6** — S3 TLS enforcement
7. **L10** — Log retention below AU-11 minimum
