locals {
  clumio_iam_role_principal = {
    intermediate_role = "arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerProtectRole"
    root              = "arn:aws:iam::${var.clumio_aws_account_id}:root"
  }
  clumio_support_role_principal = {
    intermediate_role = "arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerSupportRole"
    root              = "arn:aws:iam::${var.clumio_aws_account_id}:root"
  }
}

locals {
  region_map = {
    ap-east-1      = "ae-1"
    ap-northeast-1 = "ane-1"
    ap-northeast-2 = "ane-2"
    ap-northeast-3 = "ane-3"
    ap-south-1     = "as-1"
    ap-southeast-1 = "ase-1"
    ap-southeast-2 = "ase-2"
    ca-central-1   = "cc-1"
    eu-central-1   = "ec-1"
    eu-central-2   = "ec-2"
    eu-north-1     = "en-1"
    eu-west-1      = "ew-1"
    eu-west-2      = "ew-2"
    eu-west-3      = "ew-3"
    me-south-1     = "ms-1"
    sa-east-1      = "se-1"
    us-east-1      = "ue-1"
    us-east-2      = "ue-2"
    us-west-1      = "uw-1"
    us-west-2      = "uw-2"
  }
}

locals {
  should_create_tag_event_rule = var.is_ebs_enabled || var.is_dynamodb_enabled || var.is_rds_enabled
  tag_event_rule_data_sources  = jsonencode(compact(concat(var.is_ebs_enabled ? ["ebs", "ec2"] : [""], var.is_rds_enabled ? ["rds"] : [""], var.is_dynamodb_enabled ? ["dynamodb"] : [""])))
  tag_event_rule_event_pattern = format("{\"detail\":{\"service\":%s},\"source\":[\"aws.tag\"]}", local.tag_event_rule_data_sources)
}

data "aws_caller_identity" "current" {
}

data "aws_partition" "current" {
}

data "aws_region" "current" {
}

data "aws_iam_policy_document" "aws_iam_role_document" {
  statement {
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      values   = [var.role_external_id]
      variable = "sts:ExternalId"
    }
    effect = "Allow"
    principals {
      identifiers = ["arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerProtectRole"]
      type        = "AWS"
    }
  }
}

data "aws_iam_policy_document" "aws_support_role_document" {
  # The Role can be assumed only by a single role in the Clumio control plane
  statement {
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      values   = [var.role_external_id]
      variable = "sts:ExternalId"
    }
    effect = "Allow"
    principals {
      identifiers = ["arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerSupportRole"]
      type        = "AWS"
    }
  }
}

data "aws_iam_policy_document" "clumio_base_managed_policy_document" {
  # Permission to list all policies (managed/inline) for ClumioIAMRole and ClumioSupportRole
  # Required for validating policies
  statement {
    actions = [
      "iam:ListAccountAliases"
    ]
    effect = "Allow"
    # iam:ListAccountAliases only support the all resources wildcard('*').
    resources = [
      "*"
    ]
    sid = "GetAccountFriendlyName"
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

  # Identify if a non-default region has been enabled
  statement {
    actions = [
      "account:ListRegions",
      "account:GetRegionOptStatus"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "PermissionsToIdentifyEnabledRegions"
  }

  statement {
    actions = ["sts:DecodeAuthorizationMessage"]
    effect  = "Allow"
    # sts:DecodeAuthorizationMessage only support the all resources wildcard('*').
    resources = [
      "*"
    ]
  }
}

data "aws_iam_policy_document" "clumio_drift_detect_policy_document" {
  statement {
    actions = [
      "iam:GetServiceLinkedRoleDeletionStatus",
      "iam:ListInstanceProfilesForRole",
      "iam:SimulatePrincipalPolicy",
      "iam:GetContextKeysForPrincipalPolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:GetRolePolicy",
      "iam:GetRole",
      "sns:GetTopicAttributes",
      "sns:ListSubscriptionsByTopic",
      "sns:ListTagsForResource",
      "sns:GetDataProtectionPolicy",
      "events:DescribeEventBus",
      "events:ListTagsForResource",
      "events:DescribeRule",
      "events:ListTargetsByRule"
    ]
    effect = "Allow"
    resources = compact([aws_iam_role.clumio_iam_role.arn, aws_sns_topic.clumio_event_pub.arn,
      local.should_create_tag_event_rule ? aws_cloudwatch_event_rule.clumio_tag_event_rule[0].arn : "",
      var.is_rds_enabled ? aws_cloudwatch_event_rule.clumio_rds_cloudwatch_event_rule[0].arn : "",
      var.is_rds_enabled ? aws_cloudwatch_event_rule.clumio_rds_aws_backup_cloudwatch_event_rule[0].arn : "",
      var.is_rds_enabled ? aws_cloudwatch_event_rule.clumio_rds_cloudtrail_event_rule[0].arn : "",
      var.is_dynamodb_enabled ? aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule[0].arn : "",
      var.is_dynamodb_enabled ? aws_cloudwatch_event_rule.clumio_dynamo_aws_backup_cloudwatch_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ebs_cloudwatch_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ec2_cloudwatch_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ec2_aws_backup_cloudwatch_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ebs_aws_backup_cloudwatch_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ebs_cloudtrail_event_rule[0].arn : "",
      var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ec2_cloudtrail_event_rule[0].arn : "",
      var.is_s3_enabled ? aws_cloudwatch_event_rule.clumio_s3_cloudtrail_event_rule[0].arn : "",
    var.is_s3_enabled ? aws_cloudwatch_event_rule.clumio_s3_aws_backup_cloudwatch_event_rule[0].arn : "", ])
    sid = "ReflectOnClumioCfnStack"
  }
}

data "aws_iam_policy_document" "clumio_event_pub_policy_document" {
  statement {
    actions = [
      "SNS:Publish"
    ]
    condition {
      test = "StringEquals"
      values = [
        var.aws_account_id
      ]
      variable = "AWS:SourceAccount"
    }
    effect = "Allow"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_sns_topic.clumio_event_pub.arn
    ]
    sid = "__pub_statement"
  }

  statement {
    actions = [
      "SNS:Subscribe"
    ]
    effect = "Allow"
    principals {
      identifiers = [
        "arn:aws:iam::${var.clumio_aws_account_id}:root"
      ]
      type = "AWS"
    }
    resources = [
      aws_sns_topic.clumio_event_pub.arn
    ]
    sid = "__sub_statement"
  }

  statement {
    actions = [
      "SNS:ListSubscriptionsByTopic"
    ]
    effect = "Allow"
    principals {
      identifiers = [
        "arn:aws:iam::${var.clumio_aws_account_id}:root"
      ]
      type = "AWS"
    }
    resources = [
      aws_sns_topic.clumio_event_pub.arn
    ]
    sid = "__desc_sub_statement"
  }

  statement {
    actions = [
      "SNS:Publish"
    ]
    condition {
      test = "StringEquals"
      values = [
        var.aws_account_id
      ]
      variable = "AWS:SourceAccount"
    }
    effect = "Allow"
    principals {
      identifiers = [
        "events.amazonaws.com"
      ]
      type = "Service"
    }
    resources = [
      aws_sns_topic.clumio_event_pub.arn
    ]
    sid = "AWSEvents_ClumioInventoryRule_${var.clumio_token}_clumio-publish"
  }
}

data "aws_iam_policy_document" "clumio_inventory_policy_document" {
  # Allow Clumio insight into other AWS-backed up resources
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "backup:ListProtectedResources"
      ]
      effect = "Allow"
      # backup:ListProtectedResources only support the all resources wildcard('*').
      # This cannot be further restricted to particular asset types
      resources = [
        "*"
      ]
      sid = "GetBackedUpResources"
    }
  }

  # Allow Clumio to retrieve AWS Backup Vaults
  dynamic "statement" {
    for_each = [1]
    content {
      actions = [
        "backup:ListBackupVaults"
      ]
      effect = "Allow"
      # backup:ListBackupVaults only support the all resources wildcard('*').
      # This cannot be further restricted to particular asset types
      resources = [
        "*"
      ]
      sid = "GetAWSBackupVaults"
    }
  }

  # Allow Clumio to list recovery points in backup vaults
  dynamic "statement" {
    for_each = [1]
    content {
      actions = [
        "backup:ListRecoveryPointsByBackupVault"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:backup:${var.aws_region}:${var.aws_account_id}:backup-vault:*"
      ]
      sid = "GetAWSRecoveryPoints"
    }
  }

  # Allow Clumio to get AWS Recovery Point info
  dynamic "statement" {
    for_each = [1]
    content {
      actions = [
        "backup:DescribeRecoveryPoint"
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "GetAWSRecoveryPointInfo"
    }
  }

  dynamic "statement" {
    for_each = var.is_dynamodb_enabled ? [1] : []
    content {
      actions = [
        "dynamodb:DescribeBackup",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTableReplicaAutoScaling",
        "dynamodb:ListBackups",
        "dynamodb:ListTables",
        "dynamodb:ListTagsOfResource"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
      ]
      sid = "DescribeDynamoResources"
    }
  }

  dynamic "statement" {
    for_each = var.is_dynamodb_enabled ? [1] : []
    content {
      actions = [
        "dynamodb:DescribeGlobalTable",
        "dynamodb:DescribeGlobalTableSettings",
        "dynamodb:ListGlobalTables"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:dynamodb::${var.aws_account_id}:global-table/*"
      ]
      sid = "DescribeDynamoGlobalTableResources"
    }
  }

  dynamic "statement" {
    for_each = var.is_dynamodb_enabled ? [1] : []
    content {
      actions = [
        "cloudwatch:GetMetricStatistics",
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "DDBCloudWatchMetricReadPermissions"
    }
  }

  dynamic "statement" {
    for_each = var.is_ebs_enabled ? [1] : []
    content {
      actions = [
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeInstanceCreditSpecifications",
        "ec2:DescribeInstanceTypeOfferings",
        "ec2:DescribeTags",
        "ec2:DescribeSnapshots",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeSecurityGroups"
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "DescribeEc2Resources"
    }
  }

  dynamic "statement" {
    for_each = var.is_ebs_enabled ? [1] : []
    content {
      actions = [
        "ec2:DescribeFastSnapshotRestores",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeLockedSnapshots",
        "ec2:DescribeVolumeAttribute",
        "ec2:DescribeVolumeStatus",
        "ec2:DescribeVolumes",
        "ebs:ListChangedBlocks",
        "ebs:ListSnapshotBlocks",
        "kms:DescribeKey"
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "DescribeEbsResources"
    }
  }

  # Required to describe the RDS clusters for Clumio inventory sync.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBClusters"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
      ]
      sid = "DescribeRDSClusters"
    }
  }

  # Required to describe the RDS cluster snapshots for Clumio Convert and during restore.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBClusterSnapshotAttributes",
        "rds:DescribeDBClusterSnapshots"
      ]
      effect = "Allow"
      resources = [
        # Allow actions on customer account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
        # Allow actions on clumio account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:cluster-snapshot:*"
      ]
      sid = "DescribeRDSClusterSnapshots"
    }
  }

  # Required to describe the RDS instances for Clumio inventory sync.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBInstances"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
      ]
      sid = "DescribeRDSInstances"
    }
  }

  # Required to describe the RDS snapshots for point in time backups.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBInstanceAutomatedBackups"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:auto-backup:*"
      ]
      sid = "DescribeRDSAutomatedBackups"
    }
  }

  # Required to describe the RDS instance snapshot attribute for Clumio Convert.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBSnapshotAttributes"
      ]
      effect = "Allow"
      resources = [
        # Allow actions on customer account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*",
        # Allow actions on Clumio account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:snapshot:*"
      ]
      sid = "DescribeRDSInstanceSnapshotAttributes"
    }
  }

  # Required to describe the RDS instance snapshot for Clumio Convert and during restore.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBSnapshots"
      ]
      effect = "Allow"
      resources = [
        # Allow actions on Clumio account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:db:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*",
        # Allow actions on customer account.
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:db:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:snapshot:*"
      ]
      sid = "DescribeRDSInstanceSnapshots"
    }
  }

  # Required to describe the RDS global clusters for Clumio inventory sync.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeGlobalClusters"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:global-cluster:*"
      ]
      sid = "DescribeRDSGlobalClusters"
    }
  }

  # Required to describe the RDS option groups.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeOptionGroups",
        "rds:DescribeOptionGroupOptions"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*"
      ]
      sid = "DescribeRDSOptionGroups"
    }
  }

  # Required for listing the RDS cluster/instance tags for Clumio inventory sync.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:ListTagsForResource"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
        "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
      ]
      sid = "ListingRDSTags"
    }
  }

  # Required to get the update of new RDS resource creation or update.
  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "cloudwatch:GetMetricStatistics"
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "CloudWatchMetricReadPermissions"
    }
  }

  # List all S3 buckets and get pertinent information
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetReplicationConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration"
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
        "arn:${data.aws_partition.current.partition}:s3:::*"
      ]
      sid = "DescribeS3Resources"
    }
  }


  # Get a single S3 Multi-Region Access Point
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "s3:GetMultiRegionAccessPoint",
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
        "arn:${data.aws_partition.current.partition}:s3::${var.aws_account_id}:accesspoint/*"
      ]
      sid = "GetMultiRegionAccessPoint"
    }
  }

  # List all S3 Multi-Region Access Points
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "s3:ListMultiRegionAccessPoints",
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
        "*"
      ]
      sid = "ListMultiRegionAccessPoints"
    }
  }

  # Storage lens permissions for retrieving S3 object-level metrics
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "s3:PutStorageLensConfiguration",
        "s3:PutStorageLensConfigurationTagging",
        "s3:DeleteStorageLensConfiguration",
        "s3:GetStorageLensConfiguration",
        "s3:ListStorageLensConfigurations",
        "s3:GetStorageLensConfigurationTagging"
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
        "arn:aws:s3:*:${var.aws_account_id}:storage-lens/clumio-storage-lens-*"
      ]
      sid = "StorageLens"
    }
  }

  # Get Cloudwatch Metrics for S3 buckets
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
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
  }
}

data "aws_iam_policy_document" "clumio_kms_policy_document" {
  statement {
    actions = [
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
    ]
    sid = "RequiredKmsActions"
  }
}

data "aws_iam_policy_document" "clumio_support_policy_document" {
  # Allow Clumio Support to create cases to proactively fix any issues with backups.
  statement {
    actions = [
      "support:AddAttachmentsToSet",
      "support:AddCommunicationToCase",
      "support:CreateCase",
      "support:DescribeAttachment",
      "support:DescribeCases",
      "support:DescribeCommunications",
      "support:DescribeCreateCaseOptions",
      "support:DescribeServices",
      "support:DescribeSeverityLevels",
      "support:DescribeSupportedLanguages",
      "support:DescribeTrustedAdvisorCheckRefreshStatuses",
      "support:DescribeTrustedAdvisorCheckResult",
      "support:DescribeTrustedAdvisorChecks",
      "support:DescribeTrustedAdvisorCheckSummaries"
    ]
    effect = "Allow"
    # Support actions only support the all resources wildcard('*')
    resources = [
      "*"
    ]
    sid = "AllowClumioSupportAccess"
  }
}

data "aws_iam_policy_document" "clumio_event_pub_key_policy_document" {
  count     = var.create_clumio_inventory_sns_topic_encryption_key && var.clumio_inventory_sns_topic_encryption_key == null ? 1 : 0
  version   = "2012-10-17"
  policy_id = "clumio-event-pub-key"
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      identifiers = [
        "arn:aws:iam::${var.aws_account_id}:root"
      ]
      type = "AWS"
    }
    actions = [
      "kms:*"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow EventBridge to use the key"
    effect = "Allow"
    principals {
      identifiers = [
        "events.amazonaws.com"
      ]
      type = "Service"
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid    = "Allow SNS to use the key"
    effect = "Allow"
    principals {
      identifiers = [
        "sns.amazonaws.com"
      ]
      type = "Service"
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt"
    ]
    resources = [
      "*"
    ]
    condition {
      test     = "StringEquals"
      values   = ["arn:aws:sns:${var.aws_region}:${var.aws_account_id}:ClumioInventoryTopic_${var.clumio_token}"]
      variable = "kms:EncryptionContext:aws.sns.topicArn"
    }
  }
}

resource "aws_cloudwatch_event_rule" "clumio_tag_event_rule" {
  count = local.should_create_tag_event_rule ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description   = "Watches for tag changes"
  event_pattern = local.tag_event_rule_event_pattern
  name          = "ClumioTagCloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_target" "clumio_tag_event_rule_target" {
  count     = local.should_create_tag_event_rule ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_tag_event_rule[0].name
  target_id = "clumio-publish"
}

# The base Clumio policy
resource "aws_iam_policy" "clumio_base_managed_policy" {
  count  = 1
  name   = "ClumioBaseManagedPolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_base_managed_policy_document.json
}

resource "aws_iam_role" "clumio_iam_role" {
  assume_role_policy = data.aws_iam_policy_document.aws_iam_role_document.json
  depends_on = [
    time_sleep.wait_before_create
  ]
  name                 = "ClumioIAMRole-${lookup(local.region_map, var.aws_region, "")}-${var.clumio_token}"
  path                 = var.path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.clumio_iam_role_tags
}

resource "aws_iam_role" "clumio_support_role" {
  assume_role_policy = data.aws_iam_policy_document.aws_support_role_document.json
  count              = 1
  depends_on = [
    time_sleep.wait_before_create
  ]
  name                 = "ClumioSuppt-${var.aws_region}-${var.clumio_token}"
  path                 = var.path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.clumio_iam_role_tags
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_base_managed_policy_attachment" {
  count = 1
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_base_managed_policy
  ]
  policy_arn = aws_iam_policy.clumio_base_managed_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

# The Clumio Drift Detection policy
resource "aws_iam_role_policy" "clumio_drift_detect_policy" {
  name   = "ClumioDriftDetectPolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_drift_detect_policy_document.json
  role   = aws_iam_role.clumio_iam_role.id
}

resource "aws_iam_role_policy" "clumio_inventory_policy" {
  name   = "ClumioInventoryPolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_inventory_policy_document.json
  role   = aws_iam_role.clumio_iam_role.id
}

resource "aws_iam_role_policy" "clumio_kms_policy" {
  name   = "ClumioKMSPolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_kms_policy_document.json
  role   = aws_iam_role.clumio_iam_role.id
}

resource "aws_iam_role_policy" "clumio_support_policy" {
  count  = 1
  name   = "ClumioSupportPolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_support_policy_document.json
  role   = aws_iam_role.clumio_support_role[0].id
}

resource "aws_kms_key" "clumio_event_pub_key" {
  count               = var.create_clumio_inventory_sns_topic_encryption_key && var.clumio_inventory_sns_topic_encryption_key == null ? 1 : 0
  description         = "KMS key for Clumio Inventory Topic."
  policy              = data.aws_iam_policy_document.clumio_event_pub_key_policy_document[0].json
  enable_key_rotation = true
  tags = {
    "Vendor" = "Clumio"
  }
}

resource "aws_sns_topic" "clumio_event_pub" {
  depends_on = [
    time_sleep.wait_before_create
  ]
  display_name      = "Clumio Inventory Topic"
  name              = "ClumioInventoryTopic_${var.clumio_token}"
  kms_master_key_id = var.clumio_inventory_sns_topic_encryption_key != null ? var.clumio_inventory_sns_topic_encryption_key : var.create_clumio_inventory_sns_topic_encryption_key ? aws_kms_key.clumio_event_pub_key[0].arn : var.clumio_inventory_sns_topic_encryption_key
}

resource "aws_sns_topic_policy" "clumio_event_pub_policy" {
  arn    = aws_sns_topic.clumio_event_pub.arn
  policy = data.aws_iam_policy_document.clumio_event_pub_policy_document.json
}

resource "clumio_post_process_aws_connection" "clumio_callback" {
  account_id          = var.aws_account_id
  clumio_event_pub_id = aws_sns_topic.clumio_event_pub.arn
  config_version      = "4.6"
  depends_on = [
    aws_iam_role.clumio_iam_role,
    time_sleep.wait_30_seconds_for_iam_propagation,
    aws_iam_policy.clumio_base_managed_policy,
    aws_iam_role_policy.clumio_drift_detect_policy,
    aws_iam_role_policy.clumio_inventory_policy,
    aws_iam_role_policy.clumio_kms_policy,
    aws_cloudwatch_event_target.clumio_tag_event_rule_target,
    aws_iam_policy.clumio_ec2_mssql_backup_restore_policy,
    aws_iam_instance_profile.clumio_ec2_mssql_ssm_instance_profile,
    aws_iam_role.clumio_ec2_mssql_ssm_instance_role_v2,
    aws_iam_role_policy.clumio_ec2_mssql_ssm_instance_policy,
    aws_iam_role.clumio_ssm_notification_role,
    aws_iam_role_policy.clumio_ssm_notification_policy,
    aws_ssm_document.ssm_document_normal_heartbeat,
    aws_ssm_document.ssm_document_system_heartbeat,
    aws_ssm_document.ssm_document_mssql_prereq_heartbeat,
    aws_ssm_document.ssm_document_ssm_check_heartbeat,
    aws_ssm_document.ssm_document_ag_database_details,
    aws_ssm_document.ssm_document_get_all_services,
    aws_ssm_document.ssm_document_get_active_fci_instance,
    aws_ssm_document.ssm_document_inventory_sync,
    aws_ssm_document.ssm_document_executable_invocation_script,
    aws_ssm_document.ssm_document_copy_host_key,
    aws_ssm_document.ssm_document_install_mssql_binaries,
    aws_ssm_document.ssm_document_upgrade_mssql_binaries,
    aws_ssm_document.ssm_document_remove_old_inventory_files,
    aws_ssm_document.ssm_document_ag_details,
    aws_ssm_document.ssm_document_change_install_path,
    aws_ssm_document.ssm_document_invoke_ps_script,
    aws_iam_policy.clumio_s3_backup_policy,
    aws_iam_policy.clumio_s3_restore_policy,
    aws_cloudwatch_event_target.clumio_s3_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_s3_aws_backup_cloudwatch_event_rule_target,
    aws_iam_role.clumio_s3_continuous_backup_event_bridge_role,
    aws_iam_policy.clumio_s3_continuous_backup_event_bridge_policy,
    aws_iam_policy.clumio_dynamodb_backup_policy,
    aws_iam_policy.clumio_dynamodb_restore_policy,
    aws_cloudwatch_event_target.clumio_dynamo_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_dynamo_aws_backup_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ebs_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ebs_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_ebs_aws_backup_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ec2_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ec2_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_ec2_aws_backup_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_rds_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_rds_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_rds_aws_backup_cloudwatch_event_rule_target
  ]
  discover_version      = "4.6"
  intermediate_role_arn = "arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerProtectRole"
  properties = {
    "ClumioS3ContinuousBackupEventBridgeRoleArn" : var.is_s3_enabled ? aws_iam_role.clumio_s3_continuous_backup_event_bridge_role[0].arn : "",
    "ClumioSSMNotificationRoleArn" : var.is_ec2_mssql_enabled ? aws_iam_role.clumio_ssm_notification_role[0].arn : "",
    "DynamoDbBackupPolicyArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_dynamodb_backup_policy[0].arn : "",
    "DynamoDbRestorePolicyArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_dynamodb_restore_policy[0].arn : "",
    "PermissionsBoundaryArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_iam_permissions_boundary[0].arn : "",
    "CreateClumioInventoryTopicEncryptionKey" : var.create_clumio_inventory_sns_topic_encryption_key,
    "ClumioInventoryTopicEncryptionKey" : var.clumio_inventory_sns_topic_encryption_key
  }
  protect_config_version             = "24.2"
  protect_dynamodb_version           = var.is_dynamodb_enabled ? "7.2" : ""
  protect_ebs_version                = var.is_ebs_enabled ? "25.1" : ""
  protect_ec2_mssql_version          = var.is_ec2_mssql_enabled ? "4.4" : ""
  protect_rds_version                = var.is_rds_enabled ? "21.0" : ""
  protect_s3_version                 = var.is_s3_enabled ? "7.1" : ""
  protect_warm_tier_dynamodb_version = var.is_dynamodb_enabled ? "6.1" : ""
  protect_warm_tier_version          = var.is_dynamodb_enabled ? "1.1" : ""
  region                             = var.aws_region
  role_arn                           = aws_iam_role.clumio_iam_role.arn
  role_external_id                   = var.role_external_id
  token                              = var.clumio_token
  wait_for_data_plane_resources      = var.wait_for_data_plane_resources
  wait_for_ingestion                 = var.wait_for_ingestion
}

resource "time_sleep" "wait_30_seconds_for_iam_propagation" {
  depends_on = [
    aws_iam_role.clumio_iam_role
  ]
  create_duration = "30s"
}

resource "time_sleep" "wait_5_seconds_for_clumio_base_managed_policy" {
  count = 1
  depends_on = [
    aws_iam_policy.clumio_base_managed_policy
  ]
  create_duration = "5s"
}

resource "time_sleep" "wait_before_create" {
  create_duration = var.wait_time_before_create
}

