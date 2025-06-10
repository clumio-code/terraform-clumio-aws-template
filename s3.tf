data "aws_iam_policy_document" "clumio_s3_backup_policy_document" {
  count = var.is_s3_enabled ? 1 : 0
  # Get Cloudwatch Metrics for S3 buckets
  statement {
    actions = [
      "cloudwatch:GetMetricStatistics"
    ]
    effect = "Allow"
    # cloudwatch:GetMetricStatistics only allows for all resources wildcard
    # This cannot be further restricted to a single asset type, i.e. S3
    resources = [
      "*"
    ]
    sid = "GetS3CloudwatchMetrics"
  }

  # Allow for Clumio Backup
  statement {
    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectTagging"
    ]

    condition {
      test = "StringLike"
      values = [
        # AWS account that will store the backed up s3 data.
        var.data_plane_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::clumio-s3-backup*",
      "arn:${local.partition}:s3:::clumio-s3-backup*/*",
      "arn:${local.partition}:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-data*"
    ]
    sid = "AllowS3CopyToClumio"
  }

  # Get AWS Org to only have to add one policy for an org
  # Instead, we would create a policy for each account
  statement {
    actions = [
      "organizations:DescribeOrganization"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "AllowDescribeOrganization"
  }

  # Get S3 bucket and object information in preparation for S3 Backup
  # Needed for Continuous Backup as well
  statement {
    actions = [
      "s3:GetInventoryConfiguration",
      "s3:PutInventoryConfiguration",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:ListBucketMultipartUploads",
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
      "s3:GetObjectVersion"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::*"
    ]
    sid = "AllowS3Backup"
  }

  # Setup bucket events to forward to EventBridge for Continuous Backup
  statement {
    actions = [
      "s3:GetBucketNotification",
      "s3:PutBucketNotification"
    ]
    condition {
      test = "StringEquals"
      values = [
        var.aws_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::*"
    ]
    sid = "AllowS3ContinuousBackup"
  }

  # Configure EventBridge rule to receive bucket events for Continuous Backup
  statement {
    actions = [
      "events:DescribeRule",
      "events:PutRule",
      "events:DeleteRule",
      "events:PutTargets",
      "events:RemoveTargets",
      "events:ListTargetsByRule"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:events:*:${data.aws_caller_identity.current.account_id}:rule/clumio-s3-event-rule-*"
    ]
    sid = "AllowS3EventRuleUpdate"
  }

  # EventBridge requires new cross account event bus targets to add IAM roles
  # This passes in that role, and is necessary for Continuous Backup
  statement {
    actions = [
      "iam:PassRole"
    ]
    condition {
      test = "StringEquals"
      values = [
        "events.amazonaws.com"
      ]
      variable = "iam:PassedToService"
    }
    effect = "Allow"
    resources = [
      aws_iam_role.clumio_s3_continuous_backup_event_bridge_role[0].arn
    ]
    sid = "AllowS3ContinuousBackupRolePassToEventBridge"
  }
}

data "aws_iam_policy_document" "clumio_s3_continuous_backup_event_bridge_policy_document" {
  # Allow for Customer events to be forwarded to arena eventbridge
  statement {
    actions = [
      "events:PutEvents"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:events:*:${var.aws_account_id}:event-bus/clumio-s3-event-bus-*",
      "arn:${local.partition}:events:*:${var.data_plane_account_id}:event-bus/clumio-s3-event-bus-*"
    ]
    sid = "AllowPutEvents"
  }
}

data "aws_iam_policy_document" "clumio_s3_continuous_backup_event_bridge_role_document" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    effect = "Allow"
    principals {
      identifiers = [
        "events.amazonaws.com"
      ]
      type = "Service"
    }
    sid = "AllowEventBridgeAssumeRole"
  }
}

data "aws_iam_policy_document" "clumio_s3_restore_policy_document" {
  count = var.is_s3_enabled ? 1 : 0
  # Allows Clumio to modify bucket contents for restore
  statement {
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectTagging",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload"
    ]
    condition {
      test = "StringEquals"
      values = [
        var.aws_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::*"
    ]
    sid = "AllowS3PutForRestores"
  }

  # Allow for copy From clumio
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
    ]

    condition {
      test = "StringLike"
      values = [
        # AWS account that will store the backed up s3 data.
        var.data_plane_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:aws:s3:::clumio-s3-backup*",
      "arn:aws:s3:::clumio-s3-backup*/*",
      "arn:aws:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-data*"
    ]
    sid = "AllowS3CopyFromClumio"
  }
}

resource "aws_cloudwatch_event_rule" "clumio_s3_cloudtrail_event_rule" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create,
    time_sleep.wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule
  ]
  description   = "Watches for bucket-level resource changes in S3 (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.s3\"], \"detail-type\": [\"AWS API Call via CloudTrail\"], \"detail\": {\"eventName\": [\"CreateBucket\", \"CreateMultiRegionAccessPoint\", \"DeleteBucket\", \"DeleteBucketLifecycle\", \"DeleteBucketPolicy\", \"DeleteBucketReplication\", \"DeleteBucketTagging\", \"DeleteBucketEncryption\", \"DeleteBucketPublicAccessBlock\", \"DeleteMultiRegionAccessPoint\", \"PutBucketAcl\", \"PutBucketLifecycle\", \"PutBucketPolicy\", \"PutBucketReplication\", \"PutBucketTagging\", \"PutBucketVersioning\", \"PutBucketEncryption\", \"PutBucketPublicAccessBlock\", \"PutBucketObjectLockConfiguration\", \"PutMultiRegionAccessPointPolicy\"], \"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioS3CloudtrailEventRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_s3_aws_backup_cloudwatch_event_rule" {
  count = var.is_s3_enabled && var.collect_inventory_aws_backup_recovery_points ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create,
    time_sleep.wait_10_seconds_before_creating_clumio_s3_aws_backup_cloudwatch_event_rule
  ]
  description   = "Watches for AWS S3 backup resource changes (Cloudwatch)."
  event_pattern = "{\"source\": [\"aws.backup\"],\"detail-type\": [\"Recovery Point State Change\"],\"detail\": {\"resourceType\": [\"S3\"], \"status\": [\"COMPLETED\", \"AVAILABLE\", \"PARTIAL\", \"EXPIRED\", \"DELETED\"]}}"
  name          = "ClumioS3AWSBackupCWRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_target" "clumio_s3_cloudtrail_event_rule_target" {
  count     = var.is_s3_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_s3_cloudtrail_event_rule[0].name
  target_id = "clumio-s3-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_s3_aws_backup_cloudwatch_event_rule_target" {
  count     = var.is_s3_enabled && var.collect_inventory_aws_backup_recovery_points ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_s3_aws_backup_cloudwatch_event_rule[0].name
  target_id = "clumio-s3-aws-backup-cwatch-publish"
}

resource "aws_iam_policy" "clumio_s3_backup_policy" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for S3 backup"
  name        = "ClumioS3BackupPolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_s3_backup_policy_document[0].json
}

resource "aws_iam_policy" "clumio_s3_restore_policy" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for S3 restore"
  name        = "ClumioS3RestorePolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_s3_restore_policy_document[0].json
}

resource "aws_iam_policy" "clumio_s3_continuous_backup_event_bridge_policy" {
  count  = var.is_s3_enabled ? 1 : 0
  name   = "ClumioS3EbPolicy-${var.aws_account_id}-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_s3_continuous_backup_event_bridge_policy_document.json
}

resource "aws_iam_role" "clumio_s3_continuous_backup_event_bridge_role" {
  assume_role_policy = data.aws_iam_policy_document.clumio_s3_continuous_backup_event_bridge_role_document.json
  count              = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name                 = "ClumioS3EbRole-${lookup(local.region_map, var.aws_region, "")}-${var.clumio_token}"
  path                 = var.path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.clumio_iam_role_tags
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_s3_backup_policy_attachment" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_s3_backup_policy
  ]
  policy_arn = aws_iam_policy.clumio_s3_backup_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_s3_restore_policy_attachment" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_s3_restore_policy
  ]
  policy_arn = aws_iam_policy.clumio_s3_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_s3_continuous_backup_event_bridge_role_policy_attachment" {
  count      = var.is_s3_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_s3_continuous_backup_event_bridge_policy[0].arn
  role       = aws_iam_role.clumio_s3_continuous_backup_event_bridge_role[0].name
}

resource "time_sleep" "wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule" {
  count           = var.is_s3_enabled ? 1 : 0
  create_duration = "10s"
}

resource "time_sleep" "wait_10_seconds_before_creating_clumio_s3_aws_backup_cloudwatch_event_rule" {
  count           = var.is_s3_enabled && var.collect_inventory_aws_backup_recovery_points ? 1 : 0
  create_duration = "10s"
}

resource "time_sleep" "wait_5_seconds_for_clumio_s3_backup_policy" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    aws_iam_policy.clumio_s3_backup_policy
  ]
  create_duration = "5s"
}

resource "time_sleep" "wait_5_seconds_for_clumio_s3_restore_policy" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    aws_iam_policy.clumio_s3_restore_policy
  ]
  create_duration = "5s"
}

