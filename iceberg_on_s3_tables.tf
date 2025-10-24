data "aws_iam_policy_document" "clumio_iceberg_on_s3_tables_backup_policy_document" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  # Customer account will have the ability to copy data to arena bucket.
  # READ access is required to make diff between source and destination.
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
      "s3:AbortMultipartUpload",
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
      "arn:${local.partition}:s3:::clumio-iceberg-backup*",
      "arn:${local.partition}:s3:::clumio-iceberg-backup*/*",
      "arn:${local.partition}:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-iceberg-data*",
      "arn:${local.partition}:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-iceberg-data*/object/*"
    ]
    sid = "AllowIcebergCopyToClumio"
  }

  # Get S3 bucket and object information in preparation for Iceberg Backup
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:ListBucketMultipartUploads"
    ]

    condition {
      test = "StringEquals"
      values = [
        # Customer account
        var.aws_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::*"
    ]
    sid = "AllowS3ReadForBackup"
  }

  # Get S3 Tables and data for Iceberg Backup
  statement {
    actions = [
      "s3tables:GetTableBucket",
      "s3tables:GetTableData",
      "s3tables:GetTable",
      "s3tables:GetTableMetadataLocation"
    ]

    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3tables:*:${var.aws_account_id}:*"
    ]
    sid = "AllowS3TablesForBackup"
  }
}

data "aws_iam_policy_document" "clumio_iceberg_on_s3_tables_restore_policy_document" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  # Customer account will have the ability to copy data to arena bucket.
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:ListBucketMultipartUploads"
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
      "arn:${local.partition}:s3:::clumio-iceberg-backup*",
      "arn:${local.partition}:s3:::clumio-iceberg-backup*/*",
      "arn:${local.partition}:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-iceberg-data*",
      "arn:${local.partition}:s3:${var.aws_region}:${var.data_plane_account_id}:accesspoint/clumio-iceberg-data*/object/*"
    ]
    sid = "AllowIcebergCopyFromClumio"
  }

  # Allows Clumio to modify bucket contents for restore.
  # READ access is required to make diff between source and destination.
  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectTagging",
      "s3:AbortMultipartUpload"
    ]

    condition {
      test = "StringEquals"
      values = [
        # Customer account
        var.aws_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3:::*"
    ]
    sid = "AllowS3ReadWriteForRestore"
  }

  # Allows Clumio to modify S3Table contents for restore
  # Ref: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsglue.html
  statement {
    actions = [
      # Note: The Create* permissions are required when a customer wants to restore into a new table.
      "s3tables:GetTableBucket",
      "s3tables:CreateTableBucket",
      "s3tables:GetNamespace",
      "s3tables:CreateNamespace",
      "s3tables:GetTable",
      "s3tables:CreateTable",
      "s3tables:GetTableData",
      "s3tables:PutTableData",
      "s3tables:GetTableMetadataLocation",
      "s3tables:UpdateTableMetadataLocation",
      "s3tables:GetTableMaintenanceConfiguration",
      "s3tables:PutTableMaintenanceConfiguration"
    ]

    condition {
      test = "StringEquals"
      values = [
        # Customer account
        var.aws_account_id
      ]
      variable = "aws:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:${local.partition}:s3tables:*:${var.aws_account_id}:*"
    ]
    sid = "AllowS3TablesForRestore"
  }
}

resource "aws_cloudwatch_event_rule" "clumio_iceberg_on_s3_tables_cloudtrail_event_rule" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create,
    time_sleep.wait_10_seconds_before_creating_clumio_iceberg_on_s3_tables_cloudtrail_event_rule
  ]
  event_pattern = jsonencode(
    {
      "source" : ["aws.s3"],
      "detail" : {
        "eventName" : [
          "CreateTableBucket",
          "DeleteTableBucket",
          "CreateNamespace",
          "DeleteNamespace",
          "CreateTable",
          "DeleteTable",
          "RenameTable",
          "PutTableBucketMaintenanceConfiguration",
          "PutTableMaintenanceConfiguration",
          "UpdateTableMetadataLocation"
        ],
        "errorCode" : [{
          "exists" : false
        }]
      }
    }
  )
  name = "ClumioIcebergS3TablesCTRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_target" "clumio_iceberg_on_s3_tables_cloudtrail_event_rule_target" {
  count     = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_iceberg_on_s3_tables_cloudtrail_event_rule[0].name
  target_id = "clumio-s3table-ctrail-publish"
}

resource "aws_iam_policy" "clumio_iceberg_on_s3_tables_backup_policy" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Clumio Managed IAM Policy for Iceberg on AWS S3 Tables Backup."
  name        = "ClumioIcebergOnS3TablesBackupPolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_iceberg_on_s3_tables_backup_policy_document[0].json
}

resource "aws_iam_policy" "clumio_iceberg_on_s3_tables_restore_policy" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Clumio Managed IAM Policy for Iceberg on AWS S3 Tables Restore."
  name        = "ClumioIcebergOnS3TablesRestorePolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_iceberg_on_s3_tables_restore_policy_document[0].json
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_iceberg_on_s3_tables_backup_policy_attachment" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_iceberg_on_s3_tables_backup_policy
  ]
  policy_arn = aws_iam_policy.clumio_iceberg_on_s3_tables_backup_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_iceberg_on_s3_tables_restore_policy_attachment" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_iceberg_on_s3_tables_restore_policy
  ]
  policy_arn = aws_iam_policy.clumio_iceberg_on_s3_tables_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "time_sleep" "wait_10_seconds_before_creating_clumio_iceberg_on_s3_tables_cloudtrail_event_rule" {
  count           = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  create_duration = "10s"
}

resource "time_sleep" "wait_5_seconds_for_clumio_iceberg_on_s3_tables_backup_policy" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    aws_iam_policy.clumio_iceberg_on_s3_tables_backup_policy
  ]
  create_duration = "5s"
}

resource "time_sleep" "wait_5_seconds_for_clumio_iceberg_on_s3_tables_restore_policy" {
  count = var.is_iceberg_on_s3_tables_enabled ? 1 : 0
  depends_on = [
    aws_iam_policy.clumio_iceberg_on_s3_tables_restore_policy
  ]
  create_duration = "5s"
}
