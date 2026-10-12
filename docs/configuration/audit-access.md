# Audit Access Configuration

This document describes how to configure IAM access to rosa-boundary audit data for retrieval and compliance purposes.

## Overview

Rosa-boundary captures comprehensive audit data across multiple AWS services. Access to this data is controlled through a managed IAM policy that can be attached to groups or roles.

**Design constraints:**
- SREs performing investigations have **no direct read access** to audit data (write-only to S3)
- Audit retrieval is initially assigned to all SREs but can be restricted to a dedicated team
- Each region has its own audit bucket and log groups, so audit access is regional
- Cross-account replication is designed but not yet activated

## What Data Is Audited

| Source | What is Captured | Retention |
|--------|------------------|-----------|
| CloudWatch `/ecs/rosa-boundary-{stage}` | Container stdout/stderr | `log_retention_days` (default: 7 days) |
| CloudWatch `/ecs/rosa-boundary-{stage}/ssm-sessions` | Full ECS Exec session I/O (KMS encrypted) | `retention_days` (default: 90 days) |
| CloudWatch `/aws/lambda/...-create-investigation` | Investigation creation, OIDC validation, group checks | `log_retention_days` (default: 7 days) |
| CloudWatch `/aws/lambda/...-reap-tasks` | Task reaping events with deadline timestamps | `log_retention_days` (default: 7 days) |
| S3 `s3://{bucket}/{cluster_id}/{investigation_id}/{YYYYMMDD}/{task_id}/` | Full `/home/sre` sync on exit (excludes credentials) | 90 days WORM (COMPLIANCE mode) |
| CloudTrail | All AWS API calls | Per CloudTrail configuration |

## Enabling Audit Access

### 1. Enable the Audit Reader Policy

Set the Terraform variable in your regional workspace:

```hcl
create_audit_reader_policy = true
```

This creates a managed IAM policy named:
```
rosa-boundary-{stage}-audit-reader-{region}
```

### 2. Attach the Policy to a Group or Role

After applying, retrieve the policy ARN:

```bash
cd deploy/regional
terraform output audit_reader_policy_arn
```

#### Option A: Create a Dedicated Audit Group

For a dedicated audit team (recommended for production):

```bash
# Create the audit group
aws iam create-group --group-name rosa-boundary-audit-readers

# Attach the audit reader policy
aws iam attach-group-policy \
  --group-name rosa-boundary-audit-readers \
  --policy-arn $(terraform output -raw audit_reader_policy_arn)

# Add users to the group
aws iam add-user-to-group \
  --group-name rosa-boundary-audit-readers \
  --user-name compliance.team.member
```

#### Option B: Attach to Existing SRE Group

For initial rollout where all SREs can access audit data:

```bash
# Attach to existing SRE group (adjust group name as needed)
aws iam attach-group-policy \
  --group-name SREOperators \
  --policy-arn $(terraform output -raw audit_reader_policy_arn)
```

#### Option C: Attach to an IAM Role

For cross-account access or service-based retrieval:

```bash
aws iam attach-role-policy \
  --role-name compliance-audit-reader-role \
  --policy-arn $(terraform output -raw audit_reader_policy_arn)
```

### 3. Multi-Region Deployment

Each region has its own audit bucket and log groups. For multi-region deployments:

1. Enable `create_audit_reader_policy = true` in each regional workspace
2. Create region-specific groups or a single group with policies from all regions:

```bash
# Example: Attach all regional policies to one group
aws iam attach-group-policy \
  --group-name rosa-boundary-audit-readers \
  --policy-arn arn:aws:iam::ACCOUNT:policy/rosa-boundary-prod-audit-reader-us-east-1

aws iam attach-group-policy \
  --group-name rosa-boundary-audit-readers \
  --policy-arn arn:aws:iam::ACCOUNT:policy/rosa-boundary-prod-audit-reader-eu-west-1
```

## What the Policy Grants

The audit reader policy provides **read-only** access to:

### CloudWatch Logs
- List and describe log groups and streams
- Read log events from:
  - Container logs: `/ecs/rosa-boundary-{stage}`
  - Session I/O: `/ecs/rosa-boundary-{stage}/ssm-sessions`
  - Lambda logs: `/aws/lambda/{project}-{stage}-*`

### S3 Audit Bucket
- List bucket contents
- Get bucket configuration (versioning, object lock)
- Read objects and object versions
- View object retention and legal hold settings
- **No write or delete permissions** (WORM enforcement)

### CloudTrail
- Query API events via `cloudtrail:LookupEvents`

### ECS and EFS (Metadata Only)
- Describe tasks (for audit correlation)
- Describe EFS access points (for investigation discovery)
- **No access to running containers or filesystems**

## Retrieving Audit Data

See the [AWS IAM Policies documentation](aws-iam-policies.md) for examples of:
- Querying CloudWatch Logs for session I/O
- Downloading S3 artifacts for specific investigations
- Looking up CloudTrail events by user or time range

## Security Considerations

### Separation of Duties
- SREs performing investigations cannot read their own audit trails
- Audit readers can see what was done but cannot modify or delete evidence
- S3 object lock (COMPLIANCE mode) prevents deletion even by root account for 90 days

### Embargo'd Investigations

For sensitive investigations requiring restricted access:

1. **Short-term**: Create a temporary audit reader group for only authorized personnel
2. **Long-term**: Consider cross-account replication to a separate audit account with stricter access controls

### Future: Cross-Account Replication

The infrastructure supports cross-account S3 replication to a dedicated audit account. When activated:

- Source account (operational): SREs write to regional audit buckets
- Destination account (audit): Compliance team has read-only access
- Additional isolation and access control in the audit account

Configuration:
```hcl
audit_replication_bucket_arn    = "arn:aws:s3:::audit-account-rosa-boundary-prod"
audit_replication_account_id    = "123456789012"
```

## Disabling Audit Access

To revoke audit access:

1. Detach the policy from all groups/roles:
   ```bash
   aws iam detach-group-policy \
     --group-name rosa-boundary-audit-readers \
     --policy-arn $(terraform output -raw audit_reader_policy_arn)
   ```

2. Optionally disable policy creation:
   ```hcl
   create_audit_reader_policy = false
   ```

3. Apply Terraform (this will delete the policy if no longer attached)

## Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `create_audit_reader_policy` | `false` | Enable creation of the audit reader IAM policy |
| `retention_days` | `90` | S3 WORM and CloudWatch session log retention |
| `log_retention_days` | `7` | CloudWatch container and Lambda log retention |
| `audit_replication_bucket_arn` | `""` | Cross-account replication destination (not yet activated) |

## Related Documentation

- [AWS IAM Policies](aws-iam-policies.md) - Full policy JSON and verification examples
- [Investigations and Tasks](../architecture/investigations-and-tasks.md) - Audit data structure and lifecycle
- [System Overview](../architecture/overview.md) - Complete audit trail architecture
