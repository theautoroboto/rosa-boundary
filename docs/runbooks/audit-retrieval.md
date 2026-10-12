# Audit Retrieval Runbook

Quick reference for retrieving rosa-boundary audit data.

## Prerequisites

You must have the `rosa-boundary-{stage}-audit-reader-{region}` IAM policy attached to your IAM user, group, or role. See [Audit Access Configuration](../configuration/audit-access.md) for setup instructions.

## Audit Data Locations

| Data Type | Location | Retention |
|-----------|----------|-----------|
| Session I/O (full terminal capture) | CloudWatch `/ecs/rosa-boundary-{stage}/ssm-sessions` | 90 days |
| Container logs | CloudWatch `/ecs/rosa-boundary-{stage}` | 7 days |
| Lambda logs (investigation creation) | CloudWatch `/aws/lambda/{project}-{stage}-create-investigation` | 7 days |
| Lambda logs (task reaping) | CloudWatch `/aws/lambda/{project}-{stage}-reap-tasks` | 7 days |
| Investigation artifacts | S3 `s3://{bucket}/{cluster_id}/{investigation_id}/{YYYYMMDD}/{task_id}/` | 90 days WORM |
| API events | CloudTrail | Per CloudTrail configuration |

## Quick Lookups

### Find All Activity for an Investigation

```bash
CLUSTER_ID="rosa-prod-01"
INVESTIGATION_ID="INC-12345"

# List all S3 artifacts for this investigation
aws s3 ls s3://rosa-boundary-prod-audit/${CLUSTER_ID}/${INVESTIGATION_ID}/ --recursive

# Search CloudWatch Logs for the investigation
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --filter-pattern "${INVESTIGATION_ID}"
```

### Find Activity by User

```bash
USERNAME="alice@example.com"

# CloudTrail API events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=${USERNAME} \
  --max-results 50

# CloudWatch session logs (text search)
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --filter-pattern "${USERNAME}" \
  --start-time $(date -d '7 days ago' +%s)000
```

### Find Activity by Date Range

```bash
START_TIME=$(date -d '2026-10-01' +%s)000  # milliseconds
END_TIME=$(date -d '2026-10-12' +%s)000

# List S3 objects in date range
aws s3api list-objects-v2 \
  --bucket rosa-boundary-prod-audit \
  --query "Contents[?LastModified>='2026-10-01' && LastModified<='2026-10-12'].{Key:Key,LastModified:LastModified,Size:Size}" \
  --output table

# CloudWatch logs in date range
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --start-time ${START_TIME} \
  --end-time ${END_TIME}
```

## Detailed Retrieval Procedures

### 1. Download Investigation Artifacts from S3

```bash
CLUSTER_ID="rosa-prod-01"
INVESTIGATION_ID="INC-12345"
LOCAL_DIR="./audit-${INVESTIGATION_ID}"

# Download all artifacts for an investigation
aws s3 sync \
  s3://rosa-boundary-prod-audit/${CLUSTER_ID}/${INVESTIGATION_ID}/ \
  ${LOCAL_DIR}/ \
  --no-progress

# List what was downloaded
find ${LOCAL_DIR} -type f -exec ls -lh {} \;
```

**What you'll find:**
- `.bash_history` - Full shell command history
- Downloaded files, scripts, mustgathers
- Notes and investigation artifacts
- **Excludes**: OCM credentials, kubeconfig (task-scoped, destroyed with task)

### 2. View Session I/O from CloudWatch

```bash
# Find recent sessions
aws logs describe-log-streams \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --order-by LastEventTime \
  --descending \
  --max-items 20 \
  --query 'logStreams[].{stream:logStreamName,time:lastEventTimestamp}' \
  --output table

# View a specific session
TASK_ID="abc123..."
aws logs get-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --log-stream-name "rosa-boundary/${TASK_ID}/ecs-execute-command/rosa-boundary/..." \
  --output text

# Tail session logs in real-time (if task is still running)
aws logs tail "/ecs/rosa-boundary-prod/ssm-sessions" --follow --filter-pattern "${TASK_ID}"
```

### 3. Search Lambda Logs for Investigation Creation

```bash
INVESTIGATION_ID="INC-12345"

# Find investigation creation event
aws logs filter-log-events \
  --log-group-name "/aws/lambda/rosa-boundary-prod-create-investigation" \
  --filter-pattern "${INVESTIGATION_ID}" \
  --query 'events[].{timestamp:timestamp,message:message}' \
  --output table

# See OIDC validation and group membership checks
aws logs tail "/aws/lambda/rosa-boundary-prod-create-investigation" \
  --filter-pattern "OIDC" \
  --since 1h
```

### 4. Query CloudTrail for AWS API Calls

```bash
# Find who started a specific task
TASK_ARN="arn:aws:ecs:us-east-1:123456789012:task/rosa-boundary-prod/abc123..."

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=${TASK_ARN} \
  --max-results 10 \
  --query 'Events[].{time:EventTime,user:Username,event:EventName}' \
  --output table

# Find all ECS task launches in the last 7 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunTask \
  --start-time $(date -d '7 days ago' --iso-8601) \
  --max-results 100 \
  --query 'Events[?contains(CloudTrailEvent, `rosa-boundary`)].{time:EventTime,user:Username}' \
  --output table
```

### 5. Correlate Task ID with Investigation

```bash
TASK_ID="abc123..."

# Describe the task to get investigation tags
aws ecs describe-tasks \
  --cluster rosa-boundary-prod \
  --tasks ${TASK_ID} \
  --include TAGS \
  --query 'tasks[0].tags' \
  --output table

# Extract investigation details
aws ecs describe-tasks \
  --cluster rosa-boundary-prod \
  --tasks ${TASK_ID} \
  --include TAGS \
  --query 'tasks[0].tags[?key==`investigation_id` || key==`cluster_id` || key==`username` || key==`deadline`]' \
  --output table
```

## Common Audit Queries

### Investigation Timeline

```bash
#!/bin/bash
# audit-timeline.sh - Generate investigation timeline

INVESTIGATION_ID=$1
CLUSTER_ID=$2

echo "=== Investigation Timeline for ${INVESTIGATION_ID} ==="
echo

echo "1. S3 Artifacts:"
aws s3 ls s3://rosa-boundary-prod-audit/${CLUSTER_ID}/${INVESTIGATION_ID}/ --recursive \
  | awk '{print $1, $2, $4}'
echo

echo "2. CloudWatch Session Activity:"
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --filter-pattern "${INVESTIGATION_ID}" \
  --query 'events[].{timestamp:timestamp,message:message}' \
  --output table
echo

echo "3. Lambda Creation Events:"
aws logs filter-log-events \
  --log-group-name "/aws/lambda/rosa-boundary-prod-create-investigation" \
  --filter-pattern "${INVESTIGATION_ID}" \
  --query 'events[].message' \
  --output text
```

### User Activity Report

```bash
#!/bin/bash
# user-activity.sh - Generate user activity report

USERNAME=$1
START_DATE=$2  # YYYY-MM-DD
END_DATE=$3    # YYYY-MM-DD

START_TIME=$(date -d "${START_DATE}" +%s)000
END_TIME=$(date -d "${END_DATE}" +%s)000

echo "=== Activity Report for ${USERNAME} (${START_DATE} to ${END_DATE}) ==="
echo

echo "1. CloudTrail API Events:"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=${USERNAME} \
  --start-time ${START_DATE} \
  --end-time ${END_DATE} \
  --query 'Events[].{Time:EventTime,Event:EventName,Resource:Resources[0].ResourceName}' \
  --output table
echo

echo "2. CloudWatch Session Logs:"
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --filter-pattern "${USERNAME}" \
  --start-time ${START_TIME} \
  --end-time ${END_TIME} \
  --query 'events[].{Time:timestamp,Stream:logStreamName}' \
  --output table
```

### Investigation Evidence Package

```bash
#!/bin/bash
# package-investigation.sh - Create complete evidence package

CLUSTER_ID=$1
INVESTIGATION_ID=$2
OUTPUT_DIR="./evidence-${INVESTIGATION_ID}-$(date +%Y%m%d)"

mkdir -p ${OUTPUT_DIR}/{s3,cloudwatch,cloudtrail}

echo "Packaging evidence for ${INVESTIGATION_ID}..."

# Download S3 artifacts
aws s3 sync \
  s3://rosa-boundary-prod-audit/${CLUSTER_ID}/${INVESTIGATION_ID}/ \
  ${OUTPUT_DIR}/s3/

# Export CloudWatch session logs
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-prod/ssm-sessions" \
  --filter-pattern "${INVESTIGATION_ID}" \
  --output json > ${OUTPUT_DIR}/cloudwatch/session-logs.json

# Export Lambda logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/rosa-boundary-prod-create-investigation" \
  --filter-pattern "${INVESTIGATION_ID}" \
  --output json > ${OUTPUT_DIR}/cloudwatch/lambda-create.json

# Export CloudTrail events (requires investigation start/end times)
echo "Note: CloudTrail export requires manual time range"

# Create manifest
cat > ${OUTPUT_DIR}/manifest.txt <<EOF
Investigation: ${INVESTIGATION_ID}
Cluster: ${CLUSTER_ID}
Package Date: $(date --iso-8601=seconds)
Retrieved By: $(aws sts get-caller-identity --query Arn --output text)

Contents:
$(find ${OUTPUT_DIR} -type f -exec ls -lh {} \;)
EOF

echo "Evidence package created: ${OUTPUT_DIR}"
tar czf ${OUTPUT_DIR}.tar.gz ${OUTPUT_DIR}/
echo "Compressed: ${OUTPUT_DIR}.tar.gz"
```

## Troubleshooting

### "Access Denied" when reading S3

**Problem**: `aws s3 ls s3://rosa-boundary-prod-audit/` returns AccessDenied

**Solution**: Verify the audit reader policy is attached to your IAM identity:
```bash
# Check your identity
aws sts get-caller-identity

# Check attached policies
aws iam list-attached-user-policies --user-name $(aws iam get-user --query User.UserName --output text)
# or for groups
aws iam list-attached-group-policies --group-name rosa-boundary-audit-readers
```

### "Resource not found" when querying logs

**Problem**: Log group not found or no log streams

**Possible causes**:
1. Wrong region - audit data is regional
2. No activity yet for this investigation
3. Retention period expired (90 days for sessions, 7 days for container logs)

**Solution**:
```bash
# Verify region
aws configure get region

# List all rosa-boundary log groups
aws logs describe-log-groups --log-group-name-prefix "/ecs/rosa-boundary"

# Check log group retention
aws logs describe-log-groups \
  --log-group-name-prefix "/ecs/rosa-boundary" \
  --query 'logGroups[].{name:logGroupName,retention:retentionInDays}'
```

### Session logs are encrypted / unreadable

**Problem**: CloudWatch session logs appear as binary data

**Cause**: ECS Exec session logs are KMS encrypted and should be readable via the AWS API (the audit reader policy includes KMS decrypt permissions for the exec session key).

**Solution**: Use `aws logs get-log-events` instead of manual decryption. If still unreadable, verify KMS key policy allows your IAM identity to use the key:
```bash
aws kms describe-key --key-id alias/rosa-boundary-prod-exec-session
```

## Related Documentation

- [Audit Access Configuration](../configuration/audit-access.md) - IAM setup for audit retrieval
- [System Overview](../architecture/overview.md) - Complete audit architecture
- [Investigations and Tasks](../architecture/investigations-and-tasks.md) - Audit data structure
