# IAM resources for audit data access
#
# This managed policy grants read-only access to rosa-boundary audit data:
# - CloudWatch Logs (session I/O, container logs, Lambda logs)
# - S3 audit bucket (investigation artifacts)
# - CloudTrail events
#
# Initially assigned to all SREs; can be restricted later to a dedicated audit
# team or specific individuals for embargo'd investigations.

# Managed IAM policy for audit readers
resource "aws_iam_policy" "audit_reader" {
  count       = var.create_audit_reader_policy ? 1 : 0
  name        = "${var.project}-${var.stage}-audit-reader-${var.aws_region}"
  description = "Read-only access to rosa-boundary audit data in ${var.aws_region}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs - Session I/O and container logs
      {
        Sid    = "DescribeLogGroups"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.rosa_boundary.arn,
          aws_cloudwatch_log_group.ssm_sessions.arn,
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project}-${var.stage}-*"
        ]
      },
      {
        Sid    = "ReadAuditLogs"
        Effect = "Allow"
        Action = [
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.rosa_boundary.arn}:*",
          "${aws_cloudwatch_log_group.ssm_sessions.arn}:*",
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project}-${var.stage}-*:*"
        ]
      },
      # S3 audit bucket - read-only access
      {
        Sid    = "ListAuditBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketObjectLockConfiguration"
        ]
        Resource = aws_s3_bucket.audit.arn
      },
      {
        Sid    = "GetAuditObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectRetention",
          "s3:GetObjectLegalHold"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      # CloudTrail - query API events
      {
        Sid    = "LookupCloudTrailEvents"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      # ECS - describe tasks for audit correlation
      {
        Sid    = "DescribeECSTasksForAudit"
        Effect = "Allow"
        Action = [
          "ecs:DescribeTasks",
          "ecs:ListTasks"
        ]
        Resource = "*"
      },
      # EFS - describe access points for investigation discovery
      {
        Sid    = "DescribeEFSAccessPointsForAudit"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:DescribeAccessPoints"
        ]
        Resource = aws_efs_file_system.sre_home.arn
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name        = "${var.project}-${var.stage}-audit-reader-${var.aws_region}"
    Description = "Regional audit data read access for ${var.aws_region}"
  })
}

# Output the policy ARN for attaching to groups/roles
output "audit_reader_policy_arn" {
  description = "ARN of the audit reader policy (attach to IAM groups or roles for audit access)"
  value       = var.create_audit_reader_policy ? aws_iam_policy.audit_reader[0].arn : null
}
