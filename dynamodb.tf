# The policy document contains permissions required for DynamoDB Snap and SecureVault backups.
data "aws_iam_policy_document" "clumio_dynamodb_backup_policy_document" {
  # Required during seed backup to export the table data to S3 and enable streams.
  statement {
    actions = [
      # Required during seed backup to export the table data to S3.
      "dynamodb:ExportTableToPointInTime",
      # Required during seed backup to enable streams on the table which is required for incremental backups.
      "dynamodb:UpdateTable"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbSecureVaultBackupTableActions"
  }

  # Required during incremental backups to use streams to capture the incremental data.
  statement {
    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*/stream/*"
    ]
    sid = "ClumioDynamoDbSecureVaultStreamActions"
  }

  # Required during seed backup to export the table data to S3.
  statement {
    actions = [
      "dynamodb:DescribeExport"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*/export/*"
    ]
    sid = "ClumioDynamoDbSecureVaultExportActions"
  }

  # Required during seed backup to upload table data to S3.
  statement {
    actions = [
      "s3:AbortMultipartUpload",
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
    condition {
      test = "StringLike"
      values = [
        var.data_plane_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:aws:s3:::clumio-ddb-export-*/*"
    ]
    sid = "ClumioDynamoDbSecureVaultExportS3Actions"
  }

  # Required to decrypt the items in the encrypted table and encrypt the S3 files.
  statement {
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
    ]
    sid = "ClumioDynamoDbKmsActions"
  }

  # Required to take backup of table data and config.
  statement {
    actions = [
      "dynamodb:CreateBackup",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:ListTagsOfResource",
      "dynamodb:UpdateContinuousBackups"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbTableActions"
  }

  # Required to delete backups during expiry or failed backups cleanup.
  statement {
    actions = [
      "dynamodb:DeleteBackup",
      "dynamodb:DescribeBackup"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*/backup/*"
    ]
    sid = "ClumioSnapDynamoDbBackupActions"
  }

  # Required to list the snaps
  statement {
    actions = [
      "dynamodb:ListBackups"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*/backup*"
    ]
    sid = "ClumioSnapDynamoDbMiscActions"
  }

  # Required to backup autoscaling config.
  statement {
    actions = [
      "application-autoscaling:DescribeScalableTargets",
      "application-autoscaling:DescribeScalingPolicies"
    ]
    condition {
      test = "StringLike"
      values = [
        "dynamodb"
      ]
      variable = "application-autoscaling:service-namespace"
    }
    effect = "Allow"
    # Region wildcard is needed because Point-in-time Restore fetches the live Auto-scaling configuration
    # from the source table and uses them to update the target table configuration.
    resources = [
      "arn:${data.aws_partition.current.partition}:application-autoscaling:*:${var.aws_account_id}:scalable-target/*"
    ]
    sid = "ClumioDynamoDbAutoScalingActions"
  }
}

# The policy document contains permissions required for DynamoDB Snap and SecureVault restores.
data "aws_iam_policy_document" "clumio_dynamodb_restore_policy_document" {
  # Required to decrypt the S3 files and encrypt the restored table items.
  statement {
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
    ]
    sid = "AllowClumioDynamoDbSecureVaultKmsAccess"
  }

  # Required to restore table, global table replica and update it with the same config of the
  # backup. Replica restores require the restore role to have the following permissions in the
  # replica destination region.
  # Refer: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2gt_IAM.html
  statement {
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:CreateTableReplica",
      "dynamodb:UpdateTableReplicaAutoScaling",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchWriteItem"
    ]
    effect = "Allow"
    # Region requires a wild card to support cross region replica restore.
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:*:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDBSecureVaultGlobalTableActions"
  }

  # Required to restore to a new table from S3 files.
  statement {
    actions = [
      "dynamodb:ImportTable",
      "dynamodb:DescribeImport"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbSecureVaultImportActions"
  }

  # Required to restore to a new table from S3 files.
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:s3:::clumio-ddb-export-*/*",
      "arn:aws:s3:::clumio-ddb-export-*"
    ]
    sid = "ClumioDynamoDbSecureVaultImportFromS3Actions"
  }

  # Required by the ImportTable API that is used during restores.
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
      "logs:PutRetentionPolicy"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws-dynamodb/imports:*",
      "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.aws_account_id}:log-group::log-stream:*"
    ]
    sid = "ClumioDynamoDbSecureVaultCloudWatchActions"
  }

  # Required to restore from a snap.
  # Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/backuprestore_IAM.html
  statement {
    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:DeleteItem",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
      "dynamodb:UpdateItem",
      "dynamodb:UpdateTimeToLive",
      # Required to delete table during failed restore cleanup.
      "dynamodb:DeleteTable"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbTableActions"
  }

  # Required to restore from a snap.
  statement {
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:RestoreTableFromBackup",
      "dynamodb:RestoreTableToPointInTime"
    ]
    effect = "Allow"
    # Region requires a wild card to support cross region restores for snap and PITR.
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:*:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbRestoreTableActions"
  }

  # Required to restore autoscaling settings of the DynamoDB table provisioned throughput.
  # Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.HowTo.SDK.html
  statement {
    actions = [
      "application-autoscaling:PutScalingPolicy",
      "application-autoscaling:RegisterScalableTarget"
    ]
    condition {
      test = "StringLike"
      values = [
        "dynamodb"
      ]
      variable = "application-autoscaling:service-namespace"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:application-autoscaling:${var.aws_region}:${var.aws_account_id}:scalable-target/*"
    ]
    sid = "ClumioWarmProtectDynamoDbAutoScalingActions"
  }

  # AWSServiceRoleForApplicationAutoScaling_DynamoDBTable is automatically created when we call RegisterScalableTarget API
  statement {
    actions = [
      "iam:CreateServiceLinkedRole"
    ]
    condition {
      test = "StringLike"
      values = [
        "dynamodb.application-autoscaling.amazonaws.com"
      ]
      variable = "iam:AWSServiceName"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
    ]
    sid = "ClumioWarmProtectCreateDynamoDbAutoScalingRole"
  }

  # Required for cross region snap and PITR restores having autoscaling settings.
  statement {
    actions = [
      "iam:PassRole"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
    ]
    sid = "ClumioDynamoDbAutoScalingPassRoleActions"
  }
}

data "aws_iam_policy_document" "clumio_iam_permissions_boundary_document" {
  count = var.is_dynamodb_enabled ? 1 : 0
  # Restore the items of the table
  statement {
    actions = [
      "dynamodb:BatchWriteItem",
      "dynamodb:DescribeTable"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "AllowClumioDynamoDbSecureVaultAccess"
  }

  # Required to decrypt the S3 files and encrypt the restored table items during restores.
  statement {
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
    ]
    sid = "AllowClumioDynamoDbSecureVaultKmsAccess"
  }
}

data "aws_iam_policy_document" "clumio_iam_role_policy_document" {
  count = var.is_dynamodb_enabled ? 1 : 0
  # Allow Clumio to create roles within a Permissions Boundary.
  statement {
    actions = [
      "iam:CreateRole",
      "iam:AttachRolePolicy"
    ]
    condition {
      test = "StringEquals"
      values = [
        aws_iam_policy.clumio_iam_permissions_boundary[0].arn
      ]
      variable = "iam:PermissionsBoundary"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/clumio/Clumio-DynamoDB-SecureVault-Restore-T*"
    ]
    sid = "AllowCreateRole"
  }

  # Allow Clumio to delete the roles it has created.
  statement {
    actions = [
      "iam:DetachRolePolicy",
      "iam:DeleteRole"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/clumio/Clumio-DynamoDB-SecureVault-Restore-T*"
    ]
    sid = "AllowDeleteRole"
  }
}

resource "aws_cloudwatch_event_rule" "clumio_dynamo_cloudtrail_event_rule" {
  count         = var.is_dynamodb_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in DynamoDB (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.dynamodb\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"CreateTable\",\"DeleteTable\",\"RestoreTableFromBackup\",\"RestoreTableToPointInTime\",\"UpdateTable\",\"UpdateContinuousBackups\",\"CreateBackup\",\"DeleteBackup\",\"CreateGlobalTable\",\"UpdateGlobalTable\",\"UpdateGlobalTableSettings\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioDynamoCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_target" "clumio_dynamo_cloudtrail_event_rule_target" {
  count     = var.is_dynamodb_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule[0].name
  target_id = "clumio-dynamo-ctrail-publish"
}

# The policy captures permissions required for DynamoDB Snap and SecureVault backups.
resource "aws_iam_policy" "clumio_dynamodb_backup_policy" {
  count = var.is_dynamodb_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for DynamoDB Backups."
  name        = "ClumioDynamoDbBackupPolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_dynamodb_backup_policy_document.json
}

# The policy captures permissions required for DynamoDB Snap and SecureVault restores.
resource "aws_iam_policy" "clumio_dynamodb_restore_policy" {
  count = var.is_dynamodb_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for DynamoDB Restores."
  name        = "ClumioDynamoDbRestorePolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_dynamodb_restore_policy_document.json
}

# The Permissions Boundary that defines the scope of access allowed for Clumio on creating role for DynamoDB SecureVault.
resource "aws_iam_policy" "clumio_iam_permissions_boundary" {
  count = var.is_dynamodb_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Enforces a permissions boundary for roles created by Clumio."
  name        = "ClumioIAMPermissionsBoundary-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_iam_permissions_boundary_document[0].json
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_dynamodb_backup_policy_attachment" {
  count      = var.is_dynamodb_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_dynamodb_backup_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_dynamodb_restore_policy_attachment" {
  count      = var.is_dynamodb_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_dynamodb_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

# The policy to be attached to Clumio IAM role which is needed for restoring tables that have Local Secondary Indexes (LSI).
resource "aws_iam_role_policy" "clumio_iam_role_policy" {
  count = var.is_dynamodb_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioIAMRolePolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_iam_role_policy_document[0].json
  role   = aws_iam_role.clumio_iam_role.id
}

