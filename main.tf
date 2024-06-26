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
  statement {
    actions = [
      "iam:ListAccountAliases"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "GetAccountFriendlyName"
  }

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
    effect    = "Allow"
    resources = compact([aws_iam_role.clumio_iam_role.arn, aws_sns_topic.clumio_event_pub.arn, local.should_create_tag_event_rule ? aws_cloudwatch_event_rule.clumio_tag_event_rule[0].arn : "", var.is_rds_enabled ? aws_cloudwatch_event_rule.clumio_rds_cloudwatch_event_rule[0].arn : "", var.is_rds_enabled ? aws_cloudwatch_event_rule.clumio_rds_cloudtrail_event_rule[0].arn : "", var.is_dynamodb_enabled ? aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule[0].arn : "", var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ebs_cloudwatch_event_rule[0].arn : "", var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ec2_cloudwatch_event_rule[0].arn : "", var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ebs_cloudtrail_event_rule[0].arn : "", var.is_ebs_enabled ? aws_cloudwatch_event_rule.clumio_ec2_cloudtrail_event_rule[0].arn : ""])
    sid       = "ReflectOnClumioCfnStack"
  }
}

data "aws_iam_policy_document" "clumio_dynamodb_backup_policy_document" {
  statement {
    actions = [
      "dynamodb:ExportTableToPointInTime",
      "dynamodb:UpdateTable"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbSecureVaultBackupTableActions"
  }

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
    resources = [
      "arn:${data.aws_partition.current.partition}:application-autoscaling:*:${var.aws_account_id}:scalable-target/*"
    ]
    sid = "ClumioDynamoDbAutoScalingActions"
  }
}

data "aws_iam_policy_document" "clumio_dynamodb_restore_policy_document" {
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
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:*:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDBSecureVaultGlobalTableActions"
  }

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
      "dynamodb:DeleteTable"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbTableActions"
  }

  statement {
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:RestoreTableFromBackup",
      "dynamodb:RestoreTableToPointInTime"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:dynamodb:*:${var.aws_account_id}:table/*"
    ]
    sid = "ClumioDynamoDbRestoreTableActions"
  }

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

data "aws_iam_policy_document" "clumio_ec2_backup_policy_document" {
  statement {
    actions = [
      "ec2:CreateSnapshots",
      "ec2:CreateSnapshot"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:RequestTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "CreateSnapshotWithClumioTag"
  }

  statement {
    actions = [
      "ec2:CreateSnapshots",
      "ec2:CreateSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "CreateSnapshotOnAnyVolumeOrInstance"
  }

  statement {
    actions = [
      "ec2:DeleteSnapshot"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "DeleteClumioTaggedSnapshot"
  }

  statement {
    actions = [
      "ec2:RegisterImage"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "RegisterClumioTaggedSnapshot"
  }

  statement {
    actions = [
      "ec2:DeregisterImage"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "DeregisterClumioTaggedImage"
  }

  statement {
    actions = [
      "ec2:RegisterImage"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "RegisterImage"
  }

  statement {
    actions = [
      "ec2:DeleteTags"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "DeleteTagsOnClumioTaggedResource"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test = "StringNotLike"
      values = [
        "CreateTags"
      ]
      variable = "ec2:CreateAction"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "CreateTagsOnlyWithCreateActions"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:RequestTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "CreateTagsIfRequestHasClumioTag"
  }

  statement {
    actions = [
      "ebs:ListSnapshotBlocks",
      "ebs:ListChangedBlocks",
      "ebs:GetSnapshotBlock"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "EBSReadOperations"
  }

  statement {
    actions = [
      "ec2:DescribeCapacityReservations",
      "ec2:DescribeAddresses",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeVpcs",
      "ec2:DescribeElasticGpus",
      "ec2:DescribeSubnets",
      "ec2:DescribeKeyPairs",
      "elastic-inference:DescribeAccelerators",
      "elastic-inference:DescribeAcceleratorOfferings"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "EC2DescribeOperations"
  }

  statement {
    actions = [
      "iam:GetInstanceProfile"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:instance-profile/*"
    ]
    sid = "GetInstanceProfile"
  }

  statement {
    actions = [
      "iam:GetRole"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/*"
    ]
    sid = "GetRole"
  }
}

data "aws_iam_policy_document" "clumio_ec2_mssql_backup_restore_policy_document" {
  count = var.is_ec2_mssql_enabled ? 1 : 0
  statement {
    actions = [
      "ssm:GetCommandInvocation"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "GetSSMCommandExecution"
  }

  statement {
    actions = [
      "iam:GetInstanceProfile"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:instance-profile/*"
    ]
    sid = "GetInstanceProfile"
  }

  statement {
    actions = [
      "ec2:DescribeInstances"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "DescribeEC2Resources"
  }

  statement {
    actions = [
      "ssm:SendCommand"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "ClumioDataProtectionSSMCmd"
  }

  statement {
    actions = [
      "ssm:SendCommand"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-AGDatabaseDetails-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-CopyHostKey-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-ExecutablesInvocationScript-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-GetActiveFCIInstance-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-GetAllServices-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InstallMssqlBinaries-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InventorySync-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-MSSQLPreREQ-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-NormalHeartbeat-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-SSMPreReq-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-SystemHeartbeat-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-UpgradeMssqlBinaries-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-RemoveOldInventoryFiles-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-AGDetails-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-ChangeInstallPath-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InvokePsScript-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}::document/AWSEC2-CreateVssSnapshot"
    ]
    sid = "SSMDocumentSendCommandPermission"
  }

  statement {
    actions = [
      "ssm:CancelCommand"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:*"
    ]
    sid = "ClumioDataProtectionSSMCancelCmd"
  }

  statement {
    actions = [
      "iam:GetRole"
    ]
    effect = "Allow"
    resources = [
      aws_iam_role.clumio_ssm_notification_role[0].arn
    ]
    sid = "ClumioSSMGetRole"
  }

  statement {
    actions = [
      "iam:PassRole"
    ]
    condition {
      test = "StringLike"
      values = [
        "ssm.amazonaws.com"
      ]
      variable = "iam:PassedToService"
    }
    effect = "Allow"
    resources = [
      aws_iam_role.clumio_ssm_notification_role[0].arn
    ]
    sid = "ClumioSSMPassRole"
  }

  statement {
    actions = [
      "ec2:CreateVolume"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:RequestTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "CreateVolumeWithClumioTag"
  }

  statement {
    actions = [
      "ec2:DetachVolume",
      "ec2:AttachVolume"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "AttachDetachVolumeWithClumioTag"
  }

  statement {
    actions = [
      "ec2:DetachVolume",
      "ec2:AttachVolume"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "AttachDetachVolumeFromInstanceWithClumioTag"
  }

  statement {
    actions = [
      "ec2:DeleteVolume"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "DeleteVolumeWithClumioTag"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test = "StringLike"
      values = [
        "CreateVolume"
      ]
      variable = "ec2:CreateAction"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "CreateTagsForCreateVolume"
  }

  statement {
    actions = [
      "ec2:DeleteTags"
    ]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "DeleteTagsOnClumioVolume"
  }
}

data "aws_iam_policy_document" "clumio_ec2_mssql_ssm_instance_policy_document" {
  statement {
    actions = [
      "ec2:DescribeInstances",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
      "ssm:DescribeInstanceProperties",
      "ssm:RegisterManagedInstance",
      "ssm:GetManifest",
      "ssm:PutConfigurePackageResult"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "SSMAccess"
  }

  statement {
    actions = [
      "ssm:CreateDocument",
      "ssm:AddTagsToResource",
      "ssm:DeleteDocument",
      "ssm:ListTagsForResource",
      "ssm:UpdateDocument",
      "ssm:UpdateDocumentDefaultVersion",
      "ssm:UpdateDocumentMetadata",
      "ssm:DescribeDocument"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-AGDatabaseDetails-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-CopyHostKey-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-ExecutablesInvocationScript-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-GetActiveFCIInstance-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-GetAllServices-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InstallMssqlBinaries-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InventorySync-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-MSSQLPreREQ-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-NormalHeartbeat-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-SSMPreReq-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-SystemHeartbeat-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-UpgradeMssqlBinaries-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-RemoveOldInventoryFiles-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-AGDetails-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-ChangeInstallPath-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:document/Clumio-InvokePsScript-${var.clumio_token}",
      "arn:aws:ssm:${var.aws_region}::document/AWSEC2-CreateVssSnapshot"
    ]
    sid = "SSMDocumentMaintenancePermissions"
  }

  statement {
    actions = [
      "ssm:DescribeDocumentParameters"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:document/*"
    ]
    sid = "SSMAccessForDocument"
  }

  statement {
    actions = [
      "ssm:UpdateInstanceAssociationStatus"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:association/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:managed-instance/*"
    ]
    sid = "SSMAccessForAssociation"
  }

  statement {
    actions = [
      "ssm:ListInstanceAssociations",
      "ssm:UpdateInstanceInformation"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${var.aws_account_id}:managed-instance/*"
    ]
    sid = "SSMAccessForInstance"
  }

  statement {
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "SSMControlChannels"
  }

  statement {
    actions = [
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "EC2Messages"
  }
}

data "aws_iam_policy_document" "clumio_ec2_mssql_ssm_instance_role_v2_document" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    effect = "Allow"
    principals {
      identifiers = [
        "ec2.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

data "aws_iam_policy_document" "clumio_ec2_restore_policy_document" {
  statement {
    actions = [
      "ebs:StartSnapshot"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:RequestTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "StartSnapshotWithClumioTag"
  }

  statement {
    actions = [
      "ebs:CompleteSnapshot",
      "ebs:PutSnapshotBlock"
    ]
    condition {
      test = "StringEquals"
      values = [
        "Clumio"
      ]
      variable = "aws:ResourceTag/Vendor"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "ModifySnapshotOnClumioTaggedResource"
  }

  statement {
    actions = [
      "ec2:CreateSnapshots",
      "ec2:CreateSnapshot"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "aws:RequestTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "CreateSnapshotWithRestoreTag"
  }

  statement {
    actions = [
      "ec2:CreateSnapshots",
      "ec2:CreateSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "CreateSnapshotOnAnyVolumeOrInstance"
  }

  statement {
    actions = [
      "ec2:CreateVolume"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "*"
      ]
      variable = "aws:RequestTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "CreateVolumeWithClumioRestoreTag"
  }

  statement {
    actions = [
      "ec2:DeleteVolume"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "DeleteClumioRestoredVolume"
  }

  statement {
    actions = [
      "ec2:AttachVolume"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "AttachVolumeToAnyInstance"
  }

  statement {
    actions = [
      "ec2:DetachVolume"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "DetachVolumeFromClumioRestoredInstance"
  }

  statement {
    actions = [
      "ec2:AttachVolume",
      "ec2:DetachVolume"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*"
    ]
    sid = "AttachDetachVolume"
  }

  statement {
    actions = [
      "ec2:DeregisterImage"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "DeregisterClumioRestoredImage"
  }

  statement {
    actions = [
      "ec2:RegisterImage"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "RegisterClumioRestoredSnapshot"
  }

  statement {
    actions = [
      "ec2:RegisterImage"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "RegisterClumioRestoredImage"
  }

  statement {
    actions = [
      "ec2:DeleteNetworkInterface"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
    ]
    sid = "DeleteClumioRestoredNic"
  }

  statement {
    actions = [
      "ec2:DisassociateAddress",
      "ec2:AssociateAddress"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
    ]
    sid = "ModifyClumioRestoredNic"
  }

  statement {
    actions = [
      "ec2:RunInstances"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:subnet/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:key-pair/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:security-group/*"
    ]
    sid = "RunInstance"
  }

  statement {
    actions = [
      "ec2:TerminateInstances",
      "ec2:StartInstances",
      "ec2:StopInstances"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*"
    ]
    sid = "OperationsOnClumioRestoredInstances"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test = "StringNotLike"
      values = [
        "CreateTags"
      ]
      variable = "ec2:CreateAction"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:elastic-ip/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
    ]
    sid = "CreateTagsOnlyWithCreateActions"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "clumio.restore.tag"
      ]
      variable = "aws:TagKeys"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*"
    ]
    sid = "CreateTagsIfRequestHasRestoreTag"
  }

  statement {
    actions = [
      "ec2:DeleteTags"
    ]
    condition {
      test = "ForAnyValue:StringLike"
      values = [
        "*"
      ]
      variable = "aws:ResourceTag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::image/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:volume/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:instance/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:elastic-ip/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:network-interface/*"
    ]
    sid = "DeleteTagsOnClumioRestoredResource"
  }

  statement {
    actions = [
      "iam:PassRole"
    ]
    condition {
      test = "StringLike"
      values = [
        "ec2.amazonaws.com*"
      ]
      variable = "iam:PassedToService"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/*"
    ]
    sid = "AssignClumioDataProtectionInstanceRole"
  }

  statement {
    actions = [
      "ebs:ListSnapshotBlocks",
      "ebs:ListChangedBlocks",
      "ebs:GetSnapshotBlock"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}::snapshot/*"
    ]
    sid = "EBSReadOperations"
  }

  statement {
    actions = [
      "iam:GetInstanceProfile"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:instance-profile/*"
    ]
    sid = "GetInstanceProfile"
  }

  statement {
    actions = [
      "iam:GetRole"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/*"
    ]
    sid = "GetRole"
  }

  statement {
    actions = [
      "ec2:DescribeCapacityReservations",
      "ec2:DescribeAddresses",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeVpcs",
      "ec2:DescribeElasticGpus",
      "ec2:DescribeSubnets",
      "ec2:DescribeKeyPairs",
      "elastic-inference:DescribeAccelerators",
      "elastic-inference:DescribeAcceleratorOfferings"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "EC2DescribeOperations"
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
      variable = "AWS:SourceOwner"
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

data "aws_iam_policy_document" "clumio_iam_permissions_boundary_document" {
  count = var.is_dynamodb_enabled ? 1 : 0
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

data "aws_iam_policy_document" "clumio_inventory_policy_document" {
  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "backup:ListProtectedResources"
      ]
      effect = "Allow"
      resources = [
        "*"
      ]
      sid = "GetBackedUpResources"
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
        "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/*",
        "arn:${data.aws_partition.current.partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table*"
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
        "arn:${data.aws_partition.current.partition}:dynamodb::${var.aws_account_id}:global-table/*",
        "arn:${data.aws_partition.current.partition}:dynamodb::${var.aws_account_id}:global-table*"
      ]
      sid = "DescribeDynamoGlobalTableResources"
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

  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBClusterSnapshotAttributes",
        "rds:DescribeDBClusterSnapshots"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:cluster-snapshot:*"
      ]
      sid = "DescribeRDSClusterSnapshots"
    }
  }

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

  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBSnapshotAttributes"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:snapshot:*"
      ]
      sid = "DescribeRDSInstanceSnapshotAttributes"
    }
  }

  dynamic "statement" {
    for_each = var.is_rds_enabled ? [1] : []
    content {
      actions = [
        "rds:DescribeDBSnapshots"
      ]
      effect = "Allow"
      resources = [
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:db:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:db:*",
        "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:snapshot:*"
      ]
      sid = "DescribeRDSInstanceSnapshots"
    }
  }

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

  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketPolicy",
        "s3:GetBucketTagging",
        "s3:GetReplicationConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration"
      ]
      effect = "Allow"
      resources = [
        "arn:aws:s3:::*"
      ]
      sid = "DescribeS3Resources"
    }
  }

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
      effect = "Allow"
      resources = [
        "arn:aws:s3:*:${var.aws_account_id}:storage-lens/clumio-storage-lens-*"
      ]
      sid = "StorageLens"
    }
  }

  dynamic "statement" {
    for_each = var.is_s3_enabled ? [1] : []
    content {
      actions = [
        "cloudwatch:GetMetricStatistics"
      ]
      effect = "Allow"
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

data "aws_iam_policy_document" "clumio_rds_backup_policy_document" {
  statement {
    actions = [
      "rds:CopyDBClusterSnapshot",
      "rds:ModifyDBClusterSnapshotAttribute"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:cluster-snapshot:*"
    ]
    sid = "CopyAndSharingClusterSnapshotToClumio"
  }

  statement {
    actions = [
      "rds:CopyDBSnapshot",
      "rds:ModifyDBSnapshotAttribute"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.data_plane_account_id}:og:*"
    ]
    sid = "CopyAndSharingInstanceSnapshotToClumio"
  }

  statement {
    actions = [
      "rds:CreateDBClusterSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*"
    ]
    sid = "CreateClusterSnapshotForClumioBackup"
  }

  statement {
    actions = [
      "rds:DescribeDBClusterSnapshots"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "DescribeClusterSnapshots"
  }

  statement {
    actions = [
      "rds:CreateDBSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:snapshot:*"
    ]
    sid = "CreateInstanceSnapshotForClumioBackup"
  }

  statement {
    actions = [
      "rds:DescribeDBSubnetGroups"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "BackingUpSubnetGroups"
  }

  statement {
    actions = [
      "rds:AddTagsToResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*"
    ]
    sid = "AddingClumioTagToSnapshot"
  }

  statement {
    actions = [
      "rds:ModifyOptionGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "BackingUpOptionGroups"
  }

  statement {
    actions = [
      "rds:ModifyDBCluster"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*"
    ]
    sid = "ApplyPITRConfigurationOnCluster"
  }

  statement {
    actions = [
      "rds:ModifyDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:secgrp:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*"
    ]
    sid = "ApplyPITRConfigurationOnInstance"
  }

  statement {
    actions = [
      "ec2:DescribeSecurityGroups"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "ReadRDSSecurityGroupsPermissions"
  }

  statement {
    actions = [
      "rds:ListTagsForResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:snapshot:*"
    ]
    sid = "ListClumioTagsForSnapshots"
  }

  statement {
    actions = [
      "rds:DeleteDBClusterSnapshot"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "rds:cluster-snapshot-tag/clumio.rds.snapshot.tag"
    }
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "ClusterSnapshotCleanupPermissions"
  }

  statement {
    actions = [
      "rds:DeleteDBSnapshot"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "rds:snapshot-tag/clumio.rds.snapshot.tag"
    }
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "InstanceSnapshotCleanupPermissions"
  }

  statement {
    actions = [
      "kms:CreateGrant"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:kms:*:*:key/*"
    ]
    sid = "BackupKMSPermissions"
  }
}

data "aws_iam_policy_document" "clumio_rds_restore_policy_document" {
  statement {
    actions = [
      "rds:ListTagsForResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "ListClumioTagsForRestoredTag"
  }

  statement {
    actions = [
      "rds:CreateDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:secgrp:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreInstancesInACluster"
  }

  statement {
    actions = [
      "rds:CreateDBParameterGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:pg:*"
    ]
    sid = "RestoreParameterGroups"
  }

  statement {
    actions = [
      "rds:RestoreDBInstanceFromDBSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreInstanceFromSnapshot"
  }

  statement {
    actions = [
      "rds:RestoreDBInstanceToPointInTime"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:auto-backup:*"
    ]
    sid = "RestoreInstanceToPointInTime"
  }

  statement {
    actions = [
      "rds:RestoreDBClusterFromSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreClusterFromSnapshot"
  }

  statement {
    actions = [
      "rds:RestoreDBClusterToPointInTime"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:auto-backup:*"
    ]
    sid = "RestoreClusterToPointInTime"
  }

  statement {
    actions = [
      "rds:RemoveTagsFromResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db-snapshot:*"
    ]
    sid = "RemoveClumioTagAfterRestore"
  }

  statement {
    actions = [
      "rds:AddTagsToResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "AddingClumioTagToRestoredRDSResource"
  }

  statement {
    actions = [
      "rds:CreateOptionGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "RestoreOptionGroups"
  }

  statement {
    actions = [
      "rds:CreateDBInstanceReadReplica"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:og:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:pg:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:cluster-pg:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:secgrp:*",
      "arn:${data.aws_partition.current.partition}:rds:*:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreReadReplicas"
  }

  statement {
    actions = [
      "rds:DeleteDBCluster"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "rds:cluster-tag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "ClusterCleanupPermissions"
  }

  statement {
    actions = [
      "rds:DeleteDBInstance"
    ]
    condition {
      test = "StringLike"
      values = [
        "*"
      ]
      variable = "rds:db-tag/clumio.restore.tag"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "InstanceCleanupPermissions"
  }

  statement {
    actions = [
      "rds:AddRoleToDBCluster"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "RestoreAssociatedRolesInCluster"
  }

  statement {
    actions = [
      "rds:AddRoleToDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "RestoreAssociatedRolesInInstance"
  }

  statement {
    actions = [
      "iam:PassRole"
    ]
    condition {
      test = "StringEquals"
      values = [
        "rds.amazonaws.com"
      ]
      variable = "iam:PassedToService"
    }
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/*"
    ]
    sid = "PassAssociatedRoles"
  }
}

data "aws_iam_policy_document" "clumio_s3_backup_policy_document" {
  count = var.is_s3_enabled ? 1 : 0
  statement {
    actions = [
      "cloudwatch:GetMetricStatistics"
    ]
    effect = "Allow"
    resources = [
      "*"
    ]
    sid = "GetS3CloudwatchMetrics"
  }

  statement {
    actions = [
      "s3:ListBucket",
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectTagging"
    ]
    condition {
      test = "StringEquals"
      values = [
        var.data_plane_account_id
      ]
      variable = "s3:ResourceAccount"
    }
    effect = "Allow"
    resources = [
      "arn:aws:s3:::clumio-s3-backup*",
      "arn:aws:s3:::clumio-s3-backup*/*"
    ]
    sid = "AllowS3CopyToClumio"
  }

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
      "arn:aws:s3:::*"
    ]
    sid = "AllowS3Backup"
  }

  statement {
    actions = [
      "s3:GetBucketNotification",
      "s3:PutBucketNotification"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:s3:::*"
    ]
    sid = "AllowS3ContinuousBackup"
  }

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
      "arn:aws:events:*:${data.aws_caller_identity.current.account_id}:rule/clumio-s3-event-rule-*"
    ]
    sid = "AllowS3EventRuleUpdate"
  }

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
  statement {
    actions = [
      "events:PutEvents"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:events:*:${var.aws_account_id}:event-bus/clumio-s3-event-bus-*",
      "arn:aws:events:*:${var.data_plane_account_id}:event-bus/clumio-s3-event-bus-*"
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
  statement {
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectTagging",
      "s3:DeleteObject"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:s3:::*"
    ]
    sid = "AllowS3PutForRestores"
  }
}

data "aws_iam_policy_document" "clumio_ssm_notification_policy_document" {
  statement {
    actions = [
      "sns:Publish"
    ]
    effect = "Allow"
    resources = [
      "arn:${data.aws_partition.current.partition}:sns:${var.aws_region}:${var.clumio_aws_account_id}:ClumioSSMTopic_${var.aws_account_id}_${var.aws_region}_*"
    ]
    sid = "SSMAccess"
  }
}

data "aws_iam_policy_document" "clumio_ssm_notification_role_document" {
  statement {
    actions = [
      "sts:AssumeRole"
    ]
    effect = "Allow"
    principals {
      identifiers = [
        "ssm.amazonaws.com"
      ]
      type = "Service"
    }
  }
}

data "aws_iam_policy_document" "clumio_support_policy_document" {
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
    resources = [
      "*"
    ]
    sid = "AllowClumioSupportAccess"
  }
}

resource "aws_cloudwatch_event_rule" "clumio_dynamo_cloudtrail_event_rule" {
  count         = var.is_dynamodb_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in DynamoDB (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.dynamodb\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"CreateTable\",\"DeleteTable\",\"RestoreTableFromBackup\",\"RestoreTableToPointInTime\",\"UpdateTable\",\"UpdateContinuousBackups\",\"CreateBackup\",\"DeleteBackup\",\"CreateGlobalTable\",\"UpdateGlobalTable\",\"UpdateGlobalTableSettings\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioDynamoCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ebs_cloudtrail_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EBS (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.ec2\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"DeleteSnapshot\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioEBSCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ebs_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EBS (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.ec2\"],\"detail-type\": [\"EBS Volume Notification\", \"EBS Snapshot Notification\"],\"detail\": {\"event\": [\"createVolume\",\"modifyVolume\",\"deleteVolume\",\"createSnapshot\",\"createSnapshots\",\"copySnapshot\",\"shareSnapshot\"]}}"
  name          = "ClumioEBSCloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ec2_cloudtrail_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EC2 (CloudTrail)."
  event_pattern = "{ \"source\": [\"aws.ec2\"], \"detail-type\": [\"AWS API Call via CloudTrail\"], \"detail\": { \"eventName\": [ \"CreateImage\", \"DeregisterImage\", \"DeleteImage\", \"RegisterImage\", \"CopyImage\", \"AssociateIamInstanceProfile\", \"DisassociateIamInstanceProfile\", \"ReplaceIamInstanceProfileAssociation\", \"AttachVolume\", \"DetachVolume\" ], \"errorCode\": [{\"exists\": false}] } }"
  name          = "ClumioEC2CloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ec2_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EC2 (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.ec2\"], \"detail-type\": [\"EC2 Instance State-change Notification\"], \"detail\": {\"state\": [\"running\", \"stopped\", \"terminated\"]}}"
  name          = "ClumioEC2CloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_rds_cloudtrail_event_rule" {
  count         = var.is_rds_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in RDS (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.ec2\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"DeleteDBSnapshot\",\"DeleteDBClusterSnapshot\",\"CopyDBClusterSnapshot\",\"CopyDBSnapshot\",\"CreateDBCluster\",\"DeleteDBCluster\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioRDSCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_rds_cloudwatch_event_rule" {
  count         = var.is_rds_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in RDS (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.rds\"], \"detail-type\": [\"RDS DB Instance Event\",\"RDS DB Snapshot Event\",\"RDS DB Cluster Event\",\"RDS DB Cluster Snapshot Event\" ], \"detail\": {\"SourceType\": [\"DB_INSTANCE\", \"SNAPSHOT\", \"CLUSTER\", \"CLUSTER_SNAPSHOT\"] } }"
  name          = "ClumioRDSCloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_s3_cloudtrail_event_rule" {
  count = var.is_s3_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create,
    time_sleep.wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule
  ]
  description   = "Watches for bucket-level resource changes in S3 (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.s3\"], \"detail-type\": [\"AWS API Call via CloudTrail\"], \"detail\": {\"eventName\": [\"CreateBucket\", \"DeleteBucket\", \"DeleteBucketLifecycle\", \"DeleteBucketPolicy\", \"DeleteBucketReplication\", \"DeleteBucketTagging\", \"DeleteBucketEncryption\", \"DeleteBucketPublicAccessBlock\", \"PutBucketAcl\", \"PutBucketLifecycle\", \"PutBucketPolicy\", \"PutBucketReplication\", \"PutBucketTagging\", \"PutBucketVersioning\", \"PutBucketEncryption\", \"PutBucketPublicAccessBlock\", \"PutBucketObjectLockConfiguration\"], \"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioS3CloudtrailEventRule_${var.clumio_token}"
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

resource "aws_cloudwatch_event_target" "clumio_dynamo_cloudtrail_event_rule_target" {
  count     = var.is_dynamodb_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule[0].name
  target_id = "clumio-dynamo-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_ebs_cloudtrail_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ebs_cloudtrail_event_rule[0].name
  target_id = "clumio-ebs-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_ebs_cloudwatch_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ebs_cloudwatch_event_rule[0].name
  target_id = "clumio-ebs-cwatch-publish"
}

resource "aws_cloudwatch_event_target" "clumio_ec2_cloudtrail_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ec2_cloudtrail_event_rule[0].name
  target_id = "clumio-ec2-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_ec2_cloudwatch_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ec2_cloudwatch_event_rule[0].name
  target_id = "clumio-ec2-cwatch-publish"
}

resource "aws_cloudwatch_event_target" "clumio_rds_cloudtrail_event_rule_target" {
  count     = var.is_rds_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_rds_cloudtrail_event_rule[0].name
  target_id = "clumio-rds-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_rds_cloudwatch_event_rule_target" {
  count     = var.is_rds_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_rds_cloudwatch_event_rule[0].name
  target_id = "clumio-rds-cwatch-publish"
}

resource "aws_cloudwatch_event_target" "clumio_s3_cloudtrail_event_rule_target" {
  count     = var.is_s3_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_s3_cloudtrail_event_rule[0].name
  target_id = "clumio-s3-ctrail-publish"
}

resource "aws_cloudwatch_event_target" "clumio_tag_event_rule_target" {
  count     = local.should_create_tag_event_rule ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_tag_event_rule[0].name
  target_id = "clumio-publish"
}

resource "aws_iam_instance_profile" "clumio_ec2_mssql_ssm_instance_profile" {
  count = var.is_ec2_mssql_enabled ? 1 : 0
  name  = "Clumio-SSM-IP-${var.aws_region}-${var.clumio_token}"
  path  = var.path
  role  = aws_iam_role.clumio_ec2_mssql_ssm_instance_role_v2[0].name
}

resource "aws_iam_policy" "clumio_base_managed_policy" {
  count  = 1
  name   = "ClumioBaseManagedPolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_base_managed_policy_document.json
}

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

resource "aws_iam_policy" "clumio_ec2_backup_policy" {
  count = var.is_ebs_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioEC2BackupPolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_ec2_backup_policy_document.json
}

resource "aws_iam_policy" "clumio_ec2_restore_policy" {
  count = var.is_ebs_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioEC2RestorePolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_ec2_restore_policy_document.json
}

resource "aws_iam_policy" "clumio_ec2_mssql_backup_restore_policy" {
  count = var.is_ec2_mssql_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioEC2MSSQLBackupRestorePolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_ec2_mssql_backup_restore_policy_document[0].json
}

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

resource "aws_iam_policy" "clumio_rds_backup_policy" {
  count = var.is_rds_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for RDS Snap and SecureVault in-region and cross-region backups."
  name        = "ClumioRdsBackupPolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_rds_backup_policy_document.json
}

resource "aws_iam_policy" "clumio_rds_restore_policy" {
  count = var.is_rds_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  description = "Grants access to Clumio for RDS Snap and SecureVault restores."
  name        = "ClumioRdsRestorePolicy-${var.aws_region}-${var.clumio_token}"
  path        = var.path
  policy      = data.aws_iam_policy_document.clumio_rds_restore_policy_document.json
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

resource "aws_iam_role" "clumio_ec2_mssql_ssm_instance_role_v2" {
  assume_role_policy = data.aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_role_v2_document.json
  count              = var.is_ec2_mssql_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name                 = "ClumioSSM-${var.aws_region}-${var.clumio_token}"
  path                 = var.path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.clumio_iam_role_tags
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

resource "aws_iam_role" "clumio_ssm_notification_role" {
  assume_role_policy = data.aws_iam_policy_document.clumio_ssm_notification_role_document.json
  count              = var.is_ec2_mssql_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name                 = "ClumioSSMNotifRole-${lookup(local.region_map, var.aws_region, "")}-${var.clumio_token}"
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

resource "aws_iam_role_policy_attachment" "clumio_ec2_mssql_backup_restore_policy_role_attachment" {
  count      = var.is_ec2_mssql_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_ec2_mssql_backup_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_base_managed_policy_attachment" {
  count = 1
  depends_on = [
    time_sleep.wait_5_seconds_for_clumio_base_managed_policy
  ]
  policy_arn = aws_iam_policy.clumio_base_managed_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
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

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_ec2_backup_policy_attachment" {
  count      = var.is_ebs_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_ec2_backup_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_ec2_restore_policy_attachment" {
  count      = var.is_ebs_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_ec2_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_rds_backup_policy_attachment" {
  count      = var.is_rds_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_rds_backup_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
}

resource "aws_iam_role_policy_attachment" "clumio_iam_role_clumio_rds_restore_policy_attachment" {
  count      = var.is_rds_enabled ? 1 : 0
  policy_arn = aws_iam_policy.clumio_rds_restore_policy[0].arn
  role       = aws_iam_role.clumio_iam_role.name
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

resource "aws_iam_role_policy" "clumio_drift_detect_policy" {
  name   = "ClumioDriftDetectPolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_drift_detect_policy_document.json
  role   = aws_iam_role.clumio_iam_role.id
}

resource "aws_iam_role_policy" "clumio_ec2_mssql_ssm_instance_policy" {
  count  = var.is_ec2_mssql_enabled ? 1 : 0
  name   = "Clumio-SSM-Policy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_policy_document.json
  role   = aws_iam_role.clumio_ec2_mssql_ssm_instance_role_v2[0].id
}

resource "aws_iam_role_policy" "clumio_iam_role_policy" {
  count = var.is_dynamodb_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioIAMRolePolicy-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_iam_role_policy_document[0].json
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

resource "aws_iam_role_policy" "clumio_ssm_notification_policy" {
  count  = var.is_ec2_mssql_enabled ? 1 : 0
  name   = "ClumioSSMNotificationPolicy-${var.aws_account_id}-${var.aws_region}-${var.clumio_token}"
  policy = data.aws_iam_policy_document.clumio_ssm_notification_policy_document.json
  role   = aws_iam_role.clumio_ssm_notification_role[0].id
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

resource "aws_ssm_document" "ssm_document_ag_database_details" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Ag database details\"\n  parameters:\n    InstanceName:\n      type: \"String\"\n      description: \"sql server instance name\"\n    FileName:\n      type: \"String\"\n      description: \"File name to dump tsql query output\"\n    GroupID:\n      type: \"String\"\n      description: \"AAG group id\"\n    DatabaseGroupID:\n      type: \"String\"\n      description: \"AAG database group id\"\n    Timeout:\n      type: \"String\"\n      description: \"Timeout for the TSQL Query\"\n      allowedPattern: \"[0-9]+\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2020 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for fetching details to related a specific AG database\"\n          - \"\"\n          - \"# Get-StandaloneDBDetails fetches details realted to the AG standalone database,\"\n          - \"# given group_database_id(database native id) and group_id(ag native id)\"\n          - \"function Get-AGDBDetails\"\n          - \"{\"\n          - \"    param($InstanceName, $Filename, $GroupID, $DatabaseGroupID, $Timeout)\"\n          - \"\"\n          - \"    $Query = \\\"                        ;\"\n          - \"                        WITH paginated_databases AS\"\n          - \"                        (\"\n          - \"                                 SELECT   d.name,\"\n          - \"                                          d.compatibility_level,\"\n          - \"                                          d.state,\"\n          - \"                                          d.recovery_model,\"\n          - \"                                          CONVERT(NVARCHAR, d.create_date, 127) AS create_date,\"\n          - \"                                          d.database_id,\"\n          - \"                                          d.group_database_id,\"\n          - \"                                          CASE\"\n          - \"                                                WHEN d.is_read_only = 1 Then 1\"\n          - \"                                                ELSE 0\"\n          - \"                                          END as 'is_read_only'\"\n          - \"                                 FROM     sys.databases AS d\"\n          - \"                                 WHERE    d.group_database_id = `$(database_group_id)\"\n          - \"                                 ),\"\n          - \"                         db_size AS\"\n          - \"                        (\"\n          - \"                                 SELECT   pd.database_id,\"\n          - \"                                          CONVERT(varchar,sum(cast(mf.size as BIGINT))*8) AS database_size,\"\n          - \"                                          CONVERT(varchar,sum(cast(mf.filestream_enabled as BIGINT))) AS filestream_enabled\"\n          - \"                                 FROM     paginated_databases             AS pd\"\n          - \"                                 JOIN\"\n          - \"                                  (\"\n          - \"                                            SELECT mfs.size as size,\"\n          - \"                                                  mfs.database_id,\"\n          - \"                                                  CASE\"\n          - \"                                                      WHEN mfs.type = 2 Then 1\"\n          - \"                                                      ELSE 0\"\n          - \"                                                  END as 'filestream_enabled'\"\n          - \"                                          from sys.master_files mfs\"\n          - \"                                        ) as mf\"\n          - \"                                 ON       pd.database_id=mf.database_id\"\n          - \"                                 GROUP BY pd.database_id )\"\n          - \"                        SELECT\"\n          - \"                                  ROW_NUMBER() OVER(ORDER BY (SELECT 1)) AS table_index,\"\n          - \"                                  CASE\"\n          - \"                                            WHEN ags.primary_replica = Serverproperty('ServerName')  THEN 1\"\n          - \"                                            ELSE 0\"\n          - \"                                  END AS 'from_primary_replica',\"\n          - \"                                  d.name,\"\n          - \"                                  d.compatibility_level,\"\n          - \"                                  d.state,\"\n          - \"                                  d.recovery_model,\"\n          - \"                                  d.create_date,\"\n          - \"                                  d.database_id,\"\n          - \"                                  db_size.database_size,\"\n          - \"                                  serverproperty('productversion') AS instance_version,\"\n          - \"                                  adc.group_database_id,\"\n          - \"                                  adc.group_id,\"\n          - \"                                  d.is_read_only,\"\n          - \"                                  db_size.filestream_enabled,\"\n          - \"                                  adc.synchronization_state\"\n          - \"                        FROM      paginated_databases d\"\n          - \"                        JOIN      db_size\"\n          - \"                        ON        db_size.database_id = d.database_id\"\n          - \"                        JOIN sys.dm_hadr_database_replica_states adc\"\n          - \"                        ON        d.group_database_id = adc.group_database_id\"\n          - \"                        LEFT JOIN sys.dm_hadr_availability_group_states ags\"\n          - \"                        ON        ags.group_id = adc.group_id\"\n          - \"           where adc.is_local = 1 and adc.group_id = `$(group_id);\\\"\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $databaseVars = @(\"\n          - \"        \\\"group_id='$GroupID'\\\",\"\n          - \"        \\\"database_group_id='$DatabaseGroupID'\\\"\"\n          - \"        )\"\n          - \"        $result = Invoke-Sqlcmd -ServerInstance $InstanceName -Query $Query -ErrorAction Stop -Variable $databaseVars -QueryTimeout $Timeout\"\n          - \"        $result | Export-Csv -NoTypeInformation -Path $Filename -Append -Encoding UTF8\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"    }\"\n          - \"    return\"\n          - \"}\"\n          - \"\"\n          - \"$InstanceName = \\\"{{InstanceName}}\\\"\"\n          - \"$Filename = \\\"{{FileName}}\\\"\"\n          - \"$GroupID = \\\"{{GroupID}}\\\"\"\n          - \"$DatabaseGroupID = \\\"{{DatabaseGroupID}}\\\"\"\n          - \"$Timeout = {{Timeout}}\"\n          - \"\"\n          - \"# calling into Get-AGDBDetails function to get specific AG database details\"\n          - \"Get-AGDBDetails $InstanceName $Filename $GroupID $DatabaseGroupID $Timeout\"\n          - \"type \\\"$Filename\\\"\"\n          - \"\"\n          - \"# example\"\n          - \"# Get-AGDBDetails 'AG-S2017-4\\\\AGSQL' 'C:\\\\Program Files\\\\Clumio\\\\Edge Connector\\\\mssql\\\\inv\\\\check12.csv' '2d480a5c-43e9-dcab-a838-5fdc846c4eef' 'f18c04b0-9bc0-421a-835c-30367369e339'\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-AGDatabaseDetails-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-2"
}

resource "aws_ssm_document" "ssm_document_ag_details" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Ag details\"\n  parameters:\n    InstanceName:\n      type: \"String\"\n      description: \"sql server instance name\"\n    FileName:\n      type: \"String\"\n      description: \"File name to dump tsql query output\"\n    GroupID:\n      type: \"String\"\n      description: \"AAG group id\"\n    Timeout:\n      type: \"String\"\n      description: \"Timeout for the TSQL Query\"\n      allowedPattern: \"[0-9]+\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023\"\n          - \"# Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for fetching details to related a specific AG\"\n          - \"\"\n          - \"# Get-AGDetails fetches details realted to the AG, given group_id(ag native id)\"\n          - \"function Get-AGDetails\"\n          - \"{\"\n          - \"    param($InstanceName, $Filename, $GroupID, $Timeout)\"\n          - \"\"\n          - \"    $Query = \\\"\"\n          - \"                SELECT\"\n          - \"                           ROW_NUMBER() OVER(ORDER BY (SELECT 1)) AS table_index,\"\n          - \"                           CASE\"\n          - \"                                      WHEN ags.primary_replica = Serverproperty('ServerName')  THEN 1\"\n          - \"                                      ELSE 0\"\n          - \"                           END AS 'from_primary_replica',\"\n          - \"                           ags.primary_replica,\"\n          - \"                           ar.replica_id,\"\n          - \"                           ag.group_id,\"\n          - \"                           ar.replica_server_name,\"\n          - \"                           ar.failover_mode,\"\n          - \"                           '' as synchronization_state,\"\n          - \"                           ag.name,\"\n          - \"                           ar.availability_mode\"\n          - \"                FROM       sys.availability_groups   AS ag\"\n          - \"                INNER JOIN sys.availability_replicas AS ar\"\n          - \"                ON         ag.group_id = ar.group_id\"\n          - \"                LEFT JOIN  sys.dm_hadr_availability_group_states AS ags\"\n          - \"                ON         ag.group_id = ags.group_id\"\n          - \"                where ag.group_id = `$(group_id);\"\n          - \"                \\\"\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $databaseVars = @(\"\n          - \"        \\\"group_id='$GroupID'\\\"\"\n          - \"        )\"\n          - \"        $result = Invoke-Sqlcmd -ServerInstance $InstanceName -Query $Query -ErrorAction Stop -Variable $databaseVars -QueryTimeout $Timeout\"\n          - \"        $result | Export-Csv -NoTypeInformation -Path $Filename -Append -Encoding UTF8\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"    }\"\n          - \"    return\"\n          - \"}\"\n          - \"\"\n          - \"$InstanceName = \\\"{{InstanceName}}\\\"\"\n          - \"$Filename = \\\"{{FileName}}\\\"\"\n          - \"$GroupID = \\\"{{GroupID}}\\\"\"\n          - \"$Timeout = {{Timeout}}\"\n          - \"\"\n          - \"# example\"\n          - \"# Get-AGDetails 'AG-S2017-4\\\\AGSQL' 'C:\\\\Program Files\\\\Clumio\\\\Edge Connector\\\\mssql\\\\inv\\\\check12.csv' '2d480a5c-43e9-dcab-a838-5fdc846c4eef' 10\"\n          - \"\"\n          - \"# calling into Get-AGDetails function to get specific AG details\"\n          - \"Get-AGDetails $InstanceName $Filename $GroupID $Timeout\"\n          - \"\"\n          - \"type \\\"$Filename\\\"\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-AGDetails-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_change_install_path" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Change Install Path for Clumio Binaries\"\n  parameters:\n    OldBinaryPath:\n      type: \"String\"\n      description: \"Old executables installation path\"\n    NewBinaryPath:\n      type: \"String\"\n      description: \"New executables installation path\"\n    OldTempPath:\n      type: \"String\"\n      description: \"Old temporary data installation path\"\n    NewTempPath:\n      type: \"String\"\n      description: \"New temporary data installation path\"\n    CJTrackerServiceName:\n      type: \"String\"\n      description: \"Clumio CJTracker service name\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for upgrading clumio binary and temp path\"\n          - \"\"\n          - \"function CopyFolder\"\n          - \"{\"\n          - \"    param ($old_path, $new_path)\"\n          - \"    try\"\n          - \"    {\"\n          - \"        # if old and new path is exactly the same there is no point in coping the folder\"\n          - \"        if ($old_path -eq $new_path)\"\n          - \"        {\"\n          - \"            return\"\n          - \"        }\"\n          - \"\"\n          - \"        # test if new path needs to created or already present\"\n          - \"        $new_path_exists = Test-Path $new_path\"\n          - \"        if (!$new_path_exists)\"\n          - \"        {\"\n          - \"            New-Item -ItemType Directory -Path $new_path\"\n          - \"        }\"\n          - \"\"\n          - \"        # copy all stuff except vss and logs folder, and also exclude any .bak file\"\n          - \"        ROBOCOPY $old_path $new_path /XF '*.bak' /XD 'logs', 'vss' /S /E /NP /NC\"\n          - \"\"\n          - \"        # copy cvss.exe, This will only copy the cvss exe nothing else\"\n          - \"        $old_cvss_path = $old_path + '\\\\mssql\\\\dp\\\\vss'\"\n          - \"        $new_cvss_path = $new_path + '\\\\mssql\\\\dp\\\\vss'\"\n          - \"        ROBOCOPY $old_cvss_path $new_cvss_path cvss.exe\"\n          - \"\"\n          - \"        # copy logs folder only, without any files in it\"\n          - \"        $old_log_path = $old_path + '\\\\logs'\"\n          - \"        $new_log_path = $new_path + '\\\\logs'\"\n          - \"        ROBOCOPY $old_log_path $new_log_path /XF * /S /E /NP /NC\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error 'Failed to copy folder with error'\"\n          - \"        Write-Error $_.Exception.Message\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"# ChangeInstallPaths changes the binary and temp path\"\n          - \"# Below are the steps\"\n          - \"# - Stop the CJ tracker service\"\n          - \"# - copy binary and temp folders\"\n          - \"# - update the env variables\"\n          - \"# - start cj tracker service using new cjtracker binary\"\n          - \"function ChangeInstallPaths\"\n          - \"{\"\n          - \"    param(\"\n          - \"        $old_binary_path,\"\n          - \"        $new_binary_path,\"\n          - \"        $old_temp_path,\"\n          - \"        $new_temp_path,\"\n          - \"        $cj_tracker_service_name\"\n          - \"    )\"\n          - \"\"\n          - \"    # this try catch block stops the service\"\n          - \"    try\"\n          - \"    {\"\n          - \"        # stop the service\"\n          - \"        Stop-Service $cj_tracker_service_name -ErrorAction Stop\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error 'failed to stop the cj parser service'\"\n          - \"        Write-Error $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"\"\n          - \"    # copy the folders\"\n          - \"    try\"\n          - \"    {\"\n          - \"        # copy binary path in all cases except when old binary path is same as new bianry path\"\n          - \"        if ($old_binary_path -ne $new_binary_path)\"\n          - \"        {\"\n          - \"            CopyFolder $old_binary_path $new_binary_path\"\n          - \"        }\"\n          - \"\"\n          - \"        # copy temp path only if old and new binary paths are different from old and new temp paths\"\n          - \"        if (!($old_binary_path -eq $old_temp_path -and\"\n          - \"                $new_binary_path -eq $new_temp_path) -and\"\n          - \"                ($old_temp_path -ne $new_temp_path))\"\n          - \"        {\"\n          - \"            CopyFolder $old_temp_path $new_temp_path\"\n          - \"        }\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error 'failed to copy the folders'\"\n          - \"        Write-Error $_.Exception.Message\"\n          - \"        # start the service if we fail to copy the folder so that backups can function as\"\n          - \"        # it is\"\n          - \"        Start-Service $cj_tracker_service_name\"\n          - \"        return\"\n          - \"    }\"\n          - \"\"\n          - \"    # set env variables\"\n          - \"    [System.Environment]::SetEnvironmentVariable('CLUMIO_INSTALL_DIR', $new_binary_path, 'Machine')\"\n          - \"    [System.Environment]::SetEnvironmentVariable('CLUMIO_TEMP_DIR', $new_temp_path, 'Machine')\"\n          - \"\"\n          - \"    # update the env variable and start the service\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $cj_parser_path = $new_binary_path + '\\\\mssql\\\\dp\\\\cjtracker.exe'\"\n          - \"        sc.exe config $cj_tracker_service_name binPath= $cj_parser_path\"\n          - \"\"\n          - \"        Start-Service $cj_tracker_service_name\"\n          - \"        $serviceStatus = Get-Service -Name $cj_tracker_service_name\"\n          - \"        if ($serviceStatus.Status -ne 'Running')\"\n          - \"        {\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            Write-host 'successfully started service $cj_tracker_service_name'\"\n          - \"        }\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error 'unable to start the service $cj_tracker_service_name'\"\n          - \"        Write-Error $_.Exception.Message\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"$old_binary_path = '{{OldBinaryPath}}'\"\n          - \"$new_binary_path = '{{NewBinaryPath}}'\"\n          - \"$old_temp_path = '{{OldTempPath}}'\"\n          - \"$new_temp_path = '{{NewTempPath}}'\"\n          - \"$cj_tracker_service_name = '{{CJTrackerServiceName}}'\"\n          - \"\"\n          - \"#$old_binary_path = 'C:\\\\Clumio\\\\mssqlnewtestpath'\"\n          - \"#$new_binary_path = 'C:\\\\testnew'\"\n          - \"#$old_temp_path = 'C:\\\\Clumio\\\\mssqlnewtestpath'\"\n          - \"#$new_temp_path = 'C:\\\\testnew'\"\n          - \"#$cj_tracker_service_name = 'ClumioCJTracker'\"\n          - \"\"\n          - \"ChangeInstallPaths $old_binary_path $new_binary_path $old_temp_path $new_temp_path $cj_tracker_service_name\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-ChangeInstallPath-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_copy_host_key" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Copy encryption key to the windows host\"\n  parameters:\n    AccessKeyID:\n      type: \"String\"\n      description: \"Temporary access key id of the clumio aws arena account\"\n    SecretAccessKey:\n      type: \"String\"\n      description: \"Temporary secret access key of the clumio aws arena account\"\n    SessionToken:\n      type: \"String\"\n      description: \"Temporary session token of the clumio aws arena account\"\n    Region:\n      type: \"String\"\n      description: \"region of aws of the clumio aws arena account\"\n    HostKeyFilePath:\n      type: \"String\"\n      description: \"Path to save host key\"\n    ArenaBucket:\n      type: \"String\"\n      description: \"S3 bucket to download host key\"\n    ArenaBucketKey:\n      type: \"String\"\n      description: \"S3 key to download host key\"\n    S3HostKeyUrl:\n      type: \"String\"\n      description: \"S3 url to download host key\"\n    AWSPSEnabled:\n      type: \"String\"\n      description: \"Boolean flag to use AWS powershell module for download\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"#\"\n          - \"# Powershell script set aws environment variables\"\n          - \"\"\n          - \"# reading aws related vaiables in powershell\"\n          - \"$AWS_ACCESS_KEY_ID = '{{AccessKeyID}}'\"\n          - \"$AWS_SECRET_ACCESS_KEY = '{{SecretAccessKey}}'\"\n          - \"$AWS_SESSION_TOKEN = '{{SessionToken}}'\"\n          - \"$AWS_DEFAULT_REGION = '{{Region}}'\"\n          - \"\"\n          - \"# setting aws env variables\"\n          - \"$Env:AWS_ACCESS_KEY_ID = $AWS_ACCESS_KEY_ID\"\n          - \"$Env:AWS_SECRET_ACCESS_KEY = $AWS_SECRET_ACCESS_KEY\"\n          - \"$Env:AWS_SESSION_TOKEN = $AWS_SESSION_TOKEN\"\n          - \"$Env:AWS_DEFAULT_REGION = $AWS_DEFAULT_REGION\"\n          - \"\"\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for copying host key on ec2 host\"\n          - \"Function CopyHostKey {\"\n          - \"\"\n          - \"    Param ($HostKeyFilePath, $ArenaBucket, $ArenaBucketKey, $S3HostKeyUrl, $AWSPSEnabled)\"\n          - \"    try {\"\n          - \"        # Force powershell to use tls 1.2\"\n          - \"        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\"\n          - \"        if ($AWSPSEnabled -Eq \\\"true\\\") {\"\n          - \"            Copy-S3Object -BucketName $ArenaBucket -Key $ArenaBucketKey -File $HostKeyFilePath\"\n          - \"        } else {\"\n          - \"            (New-Object Net.WebClient).DownloadFile($S3HostKeyUrl, $HostKeyFilePath)\"\n          - \"        }\"\n          - \"        Write-host \\\"successfully copied host key on host\\\"\"\n          - \"    }\"\n          - \"    catch {\"\n          - \"        Write-host \\\"unable to copy host key on host\\\"\"\n          - \"        Write-Error $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"# path for the file to be created\"\n          - \"$HostKeyFilePath = '{{HostKeyFilePath}}'\"\n          - \"# arena bucket\"\n          - \"$ArenaBucket = '{{ArenaBucket}}'\"\n          - \"# Bucket key for hostkey\"\n          - \"$ArenaBucketKey = '{{ArenaBucketKey}}'\"\n          - \"#S3 Host key url\"\n          - \"$S3HostKeyUrl = '{{S3HostKeyUrl}}'\"\n          - \"# AWS PS Enabled Feature Flag\"\n          - \"$AWSPSEnabled = '{{AWSPSEnabled}}'\"\n          - \"\"\n          - \"CopyHostKey $HostKeyFilePath $ArenaBucket $ArenaBucketKey $S3HostKeyUrl $AWSPSEnabled\"\n          - \"\"\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"#\"\n          - \"# Powershell script to unset/remove aws env variables\"\n          - \"\"\n          - \"# unset/Remove the aws env variables\"\n          - \"Remove-item Env:AWS_ACCESS_KEY_ID\"\n          - \"Remove-item Env:AWS_SECRET_ACCESS_KEY\"\n          - \"Remove-item Env:AWS_SESSION_TOKEN\"\n          - \"Remove-item Env:AWS_DEFAULT_REGION\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-CopyHostKey-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-2"
}

resource "aws_ssm_document" "ssm_document_executable_invocation_script" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Execute clumio owned executables\"\n  parameters:\n    BinaryOpID:\n      type: \"String\"\n      description: \"OpID of the binary to invoke\"\n      allowedPattern: \"[0-9]+\"\n    Flags:\n      type: \"String\"\n      description: \"Flags to invoke\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"$binary_path = (Get-ItemProperty -Path 'HKLM:SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment' -name CLUMIO_INSTALL_DIR).CLUMIO_INSTALL_DIR\"\n          - \"\"\n          - \"Switch ({{BinaryOpID}})\"\n          - \"{\"\n          - \"    1 {\"\n          - \"        $binary_suffix = \\\"\\\\hcm\\\\winhostutil\\\"\"\n          - \"    }\"\n          - \"    2 {\"\n          - \"        $binary_suffix = \\\"\\\\mssql\\\\dp\\\\uploader\\\"\"\n          - \"    }\"\n          - \"    3 {\"\n          - \"        $binary_suffix = \\\"\\\\mssql\\\\dp\\\\restoreagent\\\"\"\n          - \"    }\"\n          - \"    4 {\"\n          - \"        $binary_suffix = \\\"\\\\mssql\\\\dp\\\\dpmssqlcloudagent\\\"\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"$binary_path = $binary_path + $binary_suffix\"\n          - \"if (Test-Path $binary_path) {\"\n          - \"    # resolve the path and update the bianry path\"\n          - \"    $binary_path = Get-Item $binary_path | Select-Object -ExpandProperty Target\"\n          - \"} else {\"\n          - \"    # else add exe to binary path\"\n          - \"    $binary_path += '.exe'\"\n          - \"}\"\n          - \"\"\n          - \"$binary_path = '\\\"{0}\\\"' -f $binary_path\"\n          - \"\"\n          - \"# resolve the path and update the binary path\"\n          - \"$cmd = '& '+ $binary_path + '{{Flags}}'\"\n          - \"Invoke-Expression -Command $cmd\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-ExecutablesInvocationScript-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-4"
}

resource "aws_ssm_document" "ssm_document_get_active_fci_instance" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"get all sql services\"\n  parameters:\n    InstanceName:\n      type: \"String\"\n      description: \"FCI sql server instance name\"\n    FileName:\n      type: \"String\"\n      description: \"File name to dump output of the File\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"# Powershell script for fetching Active host for a specific FCI\"\n          - \"# Get-FCIActiveHost fetches active fci host\"\n          - \"function Get-FCIActiveHost\"\n          - \"{\"\n          - \"    param($InstanceName, $Filename)\"\n          - \"    $Query = \\\";SELECT NodeName FROM sys.dm_os_cluster_nodes where is_current_owner = 1;\\\"\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $result = Invoke-Sqlcmd -ServerInstance $InstanceName -Query $Query -ErrorAction Stop\"\n          - \"        $result | Export-Csv -NoTypeInformation -Path $Filename -Append -Encoding UTF8\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"    }\"\n          - \"    return\"\n          - \"}\"\n          - \"\"\n          - \"$InstanceName = \\\"{{InstanceName}}\\\"\"\n          - \"$Filename = \\\"{{FileName}}\\\"\"\n          - \"\"\n          - \"Get-FCIActiveHost $InstanceName $Filename\"\n          - \"type \\\"$Filename\\\"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-GetActiveFCIInstance-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_get_all_services" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"get all sql services\"\n  parameters:\n    FileName:\n      type: \"String\"\n      description: \"file path tp dump output of the script\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Load-Module will load the $name module if it is not already loaded. Will return false, if there is error in\"\n          - \"# loading the module. Else, return true.\"\n          - \"function Load-Module\"\n          - \"{\"\n          - \"    param (\"\n          - \"        [parameter(Mandatory = $true)][string] $name\"\n          - \"    )\"\n          - \"    $retVal = $true\"\n          - \"    if (!(Get-Module -Name $name))\"\n          - \"    {\"\n          - \"        $retVal = Get-Module -ListAvailable | where { $_.Name -eq $name }\"\n          - \"        if ($retVal)\"\n          - \"        {\"\n          - \"            try\"\n          - \"            {\"\n          - \"                Import-Module $name -ErrorAction SilentlyContinue\"\n          - \"            }\"\n          - \"            catch\"\n          - \"            {\"\n          - \"                $retVal = $false\"\n          - \"            }\"\n          - \"        }\"\n          - \"    }\"\n          - \"    return $retVal\"\n          - \"}\"\n          - \"\"\n          - \"# GetClusterDetails returns cluster name and id for given sql service.\"\n          - \"# If the sql service is not clustered, it returns empty strings.\"\n          - \"# It uses `Get-ClusterResource` command to list all the clustered SQL instances and then find name and id.\"\n          - \"function GetClusterDetails {\"\n          - \"    param (\"\n          - \"        [parameter(Mandatory = $true)][string] $serviceName\"\n          - \"    )\"\n          - \"    $clusterName = \\\"\\\"\"\n          - \"    $clusterId = \\\"\\\"\"\n          - \"    # Get-ClusterResource will not work if FailoverClusters module is not loaded\"\n          - \"    if (Load-Module \\\"FailoverClusters\\\")\"\n          - \"    {\"\n          - \"        try {\"\n          - \"            $get_cluster_resource = Get-ClusterResource -ErrorAction Stop  -WarningAction silentlyContinue\"\n          - \"        }\"\n          - \"        catch {\"\n          - \"            return $clusterName, $clusterId\"\n          - \"        }\"\n          - \"        try\"\n          - \"        {\"\n          - \"            # Check if the current service is default service or not\"\n          - \"            if ($serviceName -eq \\\"MSSQLSERVER\\\")\"\n          - \"            {\"\n          - \"                # Get clusterResource for given SQL Server instance\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object {$_.Name -eq \\\"SQL Server\\\"})\"\n          - \"            }\"\n          - \"            else {\"\n          - \"                # The INSTANCE_NAME part is extracted from the service name\"\n          - \"                # The serviceName is of the format MSSQL$INSTANCE_NAME, in order to fetch the\"\n          - \"                # instance name, service Name is split with respect to $\"\n          - \"                $instance_name = $serviceName.Split('$')[1]\"\n          - \"                # Get clusterResource for given SQL Server instance\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object {$_.Name -eq \\\"SQL Server ($instance_name)\\\"})\"\n          - \"            }\"\n          - \"\"\n          - \"            # If clusterResource is empty, it means the current sql service is not clustered.\"\n          - \"            if ($clusterResource -ne $null)\"\n          - \"            {\"\n          - \"                $requiredGroup = $clusterResource.OwnerGroup\"\n          - \"\"\n          - \"                # $requiredGroup stores ownerGroup of SQL Server resource for given SQL service. The cluster resource\"\n          - \"                # for SQL Network Name for given SQL service will also have same ownerGroup. Use this to find the\"\n          - \"                # corresponsing SQL Network Name resource. We can get further info about cluster from that\"\n          - \"                # SQL Network Name resource\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object { $_.ResourceType -eq \\\"Network Name\\\" -and $_.OwnerGroup -eq $requiredGroup })\"\n          - \"                if ($clusterResource -ne $null){\"\n          - \"                    $clusterName = ($clusterResource | Get-ClusterParameter -Name 'Name').Value\"\n          - \"                    $clusterId = $clusterResource.ID\"\n          - \"                }\"\n          - \"            }\"\n          - \"        }\"\n          - \"        catch\"\n          - \"        {\"\n          - \"            Write-Error  $_.Exception.Message\"\n          - \"        }\"\n          - \"    }\"\n          - \"    return $clusterName, $clusterId\"\n          - \"}\"\n          - \"\"\n          - \"\"\n          - \"# Powershell script for getting all services installed inside a host\"\n          - \"# Note: Need to run content of fci_utils.ps1 file along with this file while running SSM command.\"\n          - \"\"\n          - \"# List all SQL Server Services\"\n          - \"$services = (Get-Service -DisplayName \\\"SQL Server (*\\\")\"\n          - \"\"\n          - \"$service_info = \\\"\\\"\"\n          - \"# global variable for introducing index field for each service\"\n          - \"# which will be later used for S3 select queries\"\n          - \"$service_count = 1\"\n          - \"\"\n          - \"$domainName = (Get-WmiObject -Class Win32_ComputerSystem).Domain\"\n          - \"\"\n          - \"# loop over every service and fetch information and dump it\"\n          - \"foreach ($service in $services)\"\n          - \"{\"\n          - \"    $serviceStatue = $service.Status.value__\"\n          - \"    $serviceStartType = $service.StartType.value__\"\n          - \"\"\n          - \"    $status = 1\"\n          - \"    if ($serviceStatue -eq 4)\"\n          - \"    {\"\n          - \"        $status = 4\"\n          - \"    }\"\n          - \"    elseif (($serviceStatue -eq 7))\"\n          - \"    {\"\n          - \"        $status = 3\"\n          - \"    }\"\n          - \"    elseif (($serviceStatue -eq 1))\"\n          - \"    {\"\n          - \"        $status = 2\"\n          - \"    }\"\n          - \"\"\n          - \"    if ($serviceStartType -eq 1 -or $serviceStartType -gt 5)\"\n          - \"    {\"\n          - \"        $serviceStartType = 0\"\n          - \"    }\"\n          - \"\"\n          - \"    # Initially the SQL Instance is considered not to be part of Failover Cluster\"\n          - \"    $isClustered = $false\"\n          - \"    $clusterName = \\\"\\\"\"\n          - \"    $clusterId = \\\"\\\"\"\n          - \"    # Obtain the service name\"\n          - \"    $serviceName = $service.ServiceName\"\n          - \"\"\n          - \"    # GetClusterDetails is defined in fci_utils.ps1. Need to include content of utils.ps1 for running this script.\"\n          - \"    $clusterName, $clusterId = GetClusterDetails $serviceName\"\n          - \"\"\n          - \"    if ($clusterName -ne \\\"\\\")\"\n          - \"    {\"\n          - \"        $isClustered = $true\"\n          - \"    }\"\n          - \"\"\n          - \"    $service_info += @{\"\n          - \"        status = $status\"\n          - \"        name = $service.ServiceName\"\n          - \"        start_type = $serviceStartType\"\n          - \"        computer_name = $env:ComputerName\"\n          - \"        index = $service_count\"\n          - \"        is_clustered = $isClustered\"\n          - \"        sql_cluster_name = $clusterName\"\n          - \"        sql_cluster_id = $clusterId\"\n          - \"        domain_name = $domainName\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"\"\n          - \"    # increment the current index for each instance (mssql service)\"\n          - \"    $service_count++\"\n          - \"}\"\n          - \"$FileName = \\\"{{FileName}}\\\"\"\n          - \"\"\n          - \"# if there is no instance then service_info var will be empty string and\"\n          - \"# write-S3Obj doesn't upload empty file, this will ensure that we upload a file and\"\n          - \"# able to run s3 select query\"\n          - \"if ($service_info -eq \\\"\\\") {\"\n          - \"    $service_info = \\\"{}\\\"\"\n          - \"}\"\n          - \"\"\n          - \"$service_info | Out-File -FilePath $FileName -Encoding utf8\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-GetAllServices-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_install_mssql_binaries" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Script to install clumio binaries on the host\"\n  parameters:\n    S3BucketName:\n      type: \"String\"\n      description: \"S3 bucket to download clumio zip\"\n    S3BucketKey:\n      type: \"String\"\n      description: \"S3 key to download clumio zip\"\n    BinariesFilePath:\n      type: \"String\"\n      description: \"The path for ec2 host binaries\"\n    EC2HostBinaryPath:\n      type: \"String\"\n      description: \"Path to install executables\"\n    EC2HostTempPath:\n      type: \"String\"\n      description: \"The temporary path for the ec2 host\"\n    EC2HostServiceName:\n      type: \"String\"\n      description: \"The name of the service to be installed\"\n    EC2HostDisplayName:\n      type: \"String\"\n      description: \"The display name of the service to be installed\"\n    EC2HostServiceDescription:\n      type: \"String\"\n      description: \"The description of the service to be installed\"\n    EC2HostServicePath:\n      type: \"String\"\n      description: \"Service installation path\"\n    EC2HostCreateDirIfNotExists:\n      type: \"String\"\n      description: \"Flag to check for dir existence\"\n    EC2BinariesVersion:\n      type: \"String\"\n      description: \"Version for the biaries to be installed\"\n    EC2VersionsFileName:\n      type: \"String\"\n      description: \"Version file name\"\n    EC2ProgramDataDir:\n      type: \"String\"\n      description: \"Directory to store version info\"\n    EC2BinariesZipCheckSum:\n      type: \"String\"\n      description: \"EC2 Binaries Zip Checksum\"\n    S3ZipUrl:\n      type: \"String\"\n      description: \"S3 Zip Url\"\n    AWSPSEnabled:\n      type: \"String\"\n      description: \"Boolean flag to use AWS powershell module for download\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Creates exe path by appending version string at the end of executable name before\"\n          - \"# .exe extension\"\n          - \"function CreateExePath\"\n          - \"{\"\n          - \"    param($raw_exe_path, $version)\"\n          - \"    return $raw_exe_path + '_' + $version + '.exe'\"\n          - \"}\"\n          - \"\"\n          - \"# Powershell script for installing binaries on ec2 host\"\n          - \"Function InstallEC2Binaries {\"\n          - \"    Param ($S3BucketName, $S3BucketKey, $BinariesFilePath, $EC2HostBinaryPath,\"\n          - \"        $EC2HostTempPath, $EC2HostServiceName, $EC2HostDisplayName, $EC2HostServiceDescription,\"\n          - \"        $EC2HostServicePath,$EC2HostCreateDirIfNotExists, $EC2BinariesVersion, $EC2VersionsFileName,\"\n          - \"        $EC2ProgramDataDir, $EC2BinariesZipCheckSum, $S3ZipUrl, $AWSPSEnabled)\"\n          - \"    try {\"\n          - \"        $BinaryPathExists = Test-Path $EC2HostBinaryPath\"\n          - \"        if (!$BinaryPathExists -And ($EC2HostCreateDirIfNotExists -Eq \\\"false\\\")) {\"\n          - \"            Write-host \\\"binary path does not exists on host $EC2HostBinaryPath\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        $TempPathExists = Test-Path $EC2HostTempPath\"\n          - \"        if (!$TempPathExists -And ($EC2HostCreateDirIfNotExists -Eq \\\"false\\\")) {\"\n          - \"            Write-host \\\"temporary path does not exists on host $EC2HostTempPath\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"\"\n          - \"        # check if installation folder already exists and if non-empty return error\"\n          - \"        # directory structure should be consistent\"\n          - \"        if ($BinaryPathExists) {\"\n          - \"            $directoryInfo = Get-ChildItem $EC2HostBinaryPath | Measure-Object\"\n          - \"            if ($directoryInfo.count -ne 0)\"\n          - \"            {\"\n          - \"                Write-host \\\"binary path is non-empty $EC2HostBinaryPath\\\"\"\n          - \"                Write-Error $_.Exception.Message\"\n          - \"                return\"\n          - \"            }\"\n          - \"        }\"\n          - \"        # check if temp folder already exists and if non-empty return error\"\n          - \"        # since same binary folder directory structure is needed in temp folder\"\n          - \"        if ($TempPathExists) {\"\n          - \"            $directoryInfo = Get-ChildItem $EC2HostTempPath | Measure-Object\"\n          - \"            if ($directoryInfo.count -ne 0)\"\n          - \"            {\"\n          - \"                Write-host \\\"temp path is non-empty $EC2HostTempPath\\\"\"\n          - \"                Write-Error $_.Exception.Message\"\n          - \"                return\"\n          - \"            }\"\n          - \"        }\"\n          - \"\"\n          - \"        # check if cjparser service already exists\"\n          - \"        $currService = Get-Service -Name $EC2HostServiceName -ErrorAction Ignore\"\n          - \"        if ($currService.Length -gt 0) {\"\n          - \"            #cjparser service already exists first remove it to install it again\"\n          - \"            Stop-Service $EC2HostServiceName -ErrorAction Ignore\"\n          - \"            # Add some delay to stop the running service before removing it\"\n          - \"            Start-Sleep -Seconds 5\"\n          - \"            $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"            if ($serviceStatus.Status -eq \\\"Running\\\") {\"\n          - \"                Write-host \\\"unable to stop the existing service $EC2HostServiceName\\\"\"\n          - \"                Write-Error $_.Exception.Message\"\n          - \"                return\"\n          - \"            }\"\n          - \"            Get-CimInstance -ClassName Win32_Service -Filter \\\"Name='$EC2HostServiceName'\\\" | Remove-CimInstance\"\n          - \"            Write-host \\\"removed existing service $EC2HostServiceName before installing it again\\\"\"\n          - \"            # Add some delay to remove the existing service from the host before adding it again\"\n          - \"            Start-Sleep -Seconds 10\"\n          - \"        }\"\n          - \"        # Force powershell to use tls 1.2\"\n          - \"        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\"\n          - \"        [System.Environment]::SetEnvironmentVariable(\\\"CLUMIO_INSTALL_DIR\\\", $EC2HostBinaryPath, 'Machine')\"\n          - \"        [System.Environment]::SetEnvironmentVariable(\\\"CLUMIO_TEMP_DIR\\\", $EC2HostTempPath, 'Machine')\"\n          - \"        [System.Environment]::SetEnvironmentVariable(\\\"CLUMIO_INSTALL_VERSION\\\", $EC2BinariesVersion, 'Machine')\"\n          - \"\"\n          - \"        if ($AWSPSEnabled -Eq \\\"true\\\") {\"\n          - \"            Copy-S3Object -BucketName $S3BucketName -Key $S3BucketKey -File $BinariesFilePath\"\n          - \"        } else {\"\n          - \"            if (-Not $BinaryPathExists) {\"\n          - \"                New-Item -ItemType Directory -Force -Path $EC2HostBinaryPath\"\n          - \"            }\"\n          - \"            (New-Object Net.WebClient).DownloadFile($S3ZipUrl, $BinariesFilePath)\"\n          - \"        }\"\n          - \"        Write-host \\\"successfully downloaded file at $BinariesFilePath\\\"\"\n          - \"\"\n          - \"        $DownloadZipSHACheckSum = Get-FileHash -Algorithm sha256 $BinariesFilePath\"\n          - \"        if($DownloadZipSHACheckSum.Hash -ne  $EC2BinariesZipCheckSum) {\"\n          - \"            Write-host \\\"checksum mismatched original file hash  $EC2BinariesZipCheckSum download file hash $DownloadZipSHACheckSum\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        $PSversion = $PSVersionTable.PSVersion.Major\"\n          - \"        if ($PSversion -ge 5) {\"\n          - \"            Microsoft.PowerShell.Archive\\\\Expand-Archive -LiteralPath $BinariesFilePath -DestinationPath $EC2HostBinaryPath\"\n          - \"            Write-host \\\"successfully unzipped to $EC2HostBinaryPath\\\"\"\n          - \"        } else {\"\n          - \"            [void](New-Item -Path $EC2HostBinaryPath -ItemType Directory -Force)\"\n          - \"            $Shell = new-object -com Shell.Application\"\n          - \"            $Shell.Namespace($EC2HostBinaryPath).copyhere($Shell.NameSpace($BinariesFilePath).Items(), 0x14)\"\n          - \"            Write-host \\\"successfully unzipped to $EC2HostBinaryPath\\\"\"\n          - \"        }\"\n          - \"\"\n          - \"        # this is added so that after unzipping the file there is time to release\"\n          - \"        # handle for other process.\"\n          - \"        Start-Sleep -Seconds 5\"\n          - \"\"\n          - \"        Remove-Item -Force $BinariesFilePath -ErrorAction Ignore\"\n          - \"        Write-host \\\"deleted the zip file after unarchive $BinariesFilePath\\\"\"\n          - \"\"\n          - \"        # remove . from the versions to append it as a suffix in the execuables\"\n          - \"        $version_numer = $EC2BinariesVersion.Replace('.', '_')\"\n          - \"\"\n          - \"        # rename the exes\"\n          - \"        Rename-Item -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\dpmssqlcloudagent.exe\\\" -NewName (CreateExePath 'dpmssqlcloudagent' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\uploader.exe\\\" -NewName (CreateExePath 'uploader' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\restoreagent.exe\\\" -NewName (CreateExePath 'restoreagent' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$EC2HostBinaryPath\\\\hcm\\\\winhostutil.exe\\\" -NewName (CreateExePath 'winhostutil' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\\cvss.exe\\\" -NewName (CreateExePath 'cvss' $version_numer)\"\n          - \"\"\n          - \"        # create symlinks\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\dpmssqlcloudagent\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\dpmssqlcloudagent\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\uploader\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\uploader\\\" $version_numer)  -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\restoreagent\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\restoreagent\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\hcm\\\\winhostutil\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\hcm\\\\winhostutil\\\" $version_numer)  -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\\cvss\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\\cvss\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"\"\n          - \"        if ($EC2HostBinaryPath -ne  $EC2HostTempPath)\"\n          - \"        {\"\n          - \"            Copy-Item -Path  $EC2HostBinaryPath -Destination $EC2HostTempPath -Recurse -Container -Filter { PSIsContainer -eq $true }\"\n          - \"            Write-host \\\"successfully created the directory structure in $EC2HostTempPath\\\"\"\n          - \"        }\"\n          - \"\"\n          - \"        new-service -Name $EC2HostServiceName -DisplayName $EC2HostDisplayName -Description $EC2HostServiceDescription -BinaryPathName $EC2HostServicePath -StartupType Automatic\"\n          - \"        Write-host \\\"successfully registered service $EC2HostServiceName\\\"\"\n          - \"\"\n          - \"        Start-Service $EC2HostServiceName\"\n          - \"        $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"        if ($serviceStatus.Status -ne \\\"Running\\\") {\"\n          - \"            Write-host \\\"unable to start the service $EC2HostServiceName\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        } else {\"\n          - \"            Write-host \\\"successfully started service $EC2HostServiceName\\\"\"\n          - \"        }\"\n          - \"\"\n          - \"        New-Item -Path \\\"$env:ProgramData\\\" -Name $EC2ProgramDataDir -ItemType \\\"directory\\\" -Force\"\n          - \"        New-Item -Path \\\"$env:ProgramData\\\\$EC2ProgramDataDir\\\" -Name $EC2VersionsFileName -ItemType \\\"file\\\" -Value $EC2BinariesVersion -Force\"\n          - \"        Write-Host \\\"successfully written the versions info $EC2BinariesVersion in versions directory $env:ProgramData\\\\$EC2ProgramDataDir\\\"\"\n          - \"    }\"\n          - \"    catch {\"\n          - \"        Write-host \\\"got error in installing ec2 binaries on host\\\"\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"    Write-host \\\"successfully installed binaries at $EC2HostBinaryPath\\\"\"\n          - \"}\"\n          - \"\"\n          - \"# reading object related variable\"\n          - \"$S3BucketName = '{{S3BucketName}}'\"\n          - \"$S3BucketKey = '{{S3BucketKey}}'\"\n          - \"# BinariesFilePath is the path where s3 object will get downloaded\"\n          - \"$BinariesFilePath = '{{BinariesFilePath}}'\"\n          - \"# EC2HostBinaryPath is the path for ec2 host binaries\"\n          - \"$EC2HostBinaryPath = '{{EC2HostBinaryPath}}'\"\n          - \"# EC2HostTempPath is the temporary path for the ec2 host\"\n          - \"$EC2HostTempPath = '{{EC2HostTempPath}}'\"\n          - \"# EC2HostServiceName is the name of the service to be installed\"\n          - \"$EC2HostServiceName = '{{EC2HostServiceName}}'\"\n          - \"# EC2HostDisplayName is the display name of the service to be installed\"\n          - \"$EC2HostDisplayName = '{{EC2HostDisplayName}}'\"\n          - \"# EC2HostServiceDescription is the description of the service to be installed\"\n          - \"$EC2HostServiceDescription = '{{EC2HostServiceDescription}}'\"\n          - \"# EC2HostServicePath is the service installation path\"\n          - \"$EC2HostServicePath = '{{EC2HostServicePath}}'\"\n          - \"#Flag to check for dir existence\"\n          - \"$EC2HostCreateDirIfNotExists = '{{EC2HostCreateDirIfNotExists}}'\"\n          - \"#Version for the biaries to be installed\"\n          - \"$EC2BinariesVersion = '{{EC2BinariesVersion}}'\"\n          - \"#Version file name\"\n          - \"$EC2VersionsFileName = '{{EC2VersionsFileName}}'\"\n          - \"# Directory to store version info\"\n          - \"$EC2ProgramDataDir = '{{EC2ProgramDataDir}}'\"\n          - \"# EC2 Binaries Zip Checksum\"\n          - \"$EC2BinariesZipCheckSum = '{{EC2BinariesZipCheckSum}}'\"\n          - \"# S3 Zip Url\"\n          - \"$S3ZipUrl = '{{S3ZipUrl}}'\"\n          - \"# AWS PS Enabled Feature Flag\"\n          - \"$AWSPSEnabled = {{$AWSPSEnabled}}\"\n          - \"\"\n          - \"InstallEC2Binaries $S3BucketName $S3BucketKey $BinariesFilePath $EC2HostBinaryPath $EC2HostTempPath $EC2HostServiceName $EC2HostDisplayName $EC2HostServiceDescription $EC2HostServicePath $EC2HostCreateDirIfNotExists $EC2BinariesVersion $EC2VersionsFileName $EC2ProgramDataDir $EC2BinariesZipCheckSum $S3ZipUrl $AWSPSEnabled\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-InstallMssqlBinaries-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-3"
}

resource "aws_ssm_document" "ssm_document_inventory_sync" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Script to get mssql server instance data in CSV format\"\n  parameters:\n    InstanceName:\n      type: \"String\"\n      description: \"FCI sql server instance name\"\n    FilenamePrefix:\n      type: \"String\"\n      description: \"File path prefix to dump output of the Files\"\n    Limit:\n      type: \"String\"\n      description: \"Numbers of records to fetch in sys.database tables\"\n      default: \"20\"\n      allowedPattern: \"[0-9]+\"\n    Timeout:\n      type: \"String\"\n      description: \"Timeout for running tSQL command\"\n      default: \"180\"\n      allowedPattern: \"[0-9]+\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2020 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for doing inventory, for instance, using TSQL commands\"\n          - \"\"\n          - \"# style guid followed lightly\"\n          - \"# https://github.com/PoshCode/PowerShellPracticeAndStyle/blob/master/Style-Guide/Code-Layout-and-Formatting.md\"\n          - \"\"\n          - \"# used http://www.dpriver.com/pp/sqlformat.htm for formatting TSQL commands\"\n          - \"\"\n          - \"# there are many enums which are being queried from SQL server using T-SQL like recovery_model, database_state.. etc.,\"\n          - \"# all enum conversion is happening at computeDiff state at computeDiff step at invsrvmssql host sync workflow step\"\n          - \"\"\n          - \"# Invoke-SQLQuery invokes SQL query and returns the result; it is a generic wrapper that dumps query results to\"\n          - \"# the specified file supports pagination ( with argument Ispaginated as 1) Dumps page by page in the same file.\"\n          - \"# Avoid count query, which is expensive on the SQL Server. Limit parameter is used for pagination; it limits the number\"\n          - \"# of rows fetched in paginated query\"\n          - \"function Invoke-SQLQuery\"\n          - \"{\"\n          - \"    param($InstanceName, $Query, $Filename, $Limit, $IsPaginated, $Timeout)\"\n          - \"    if ($IsPaginated -eq 0)\"\n          - \"    {\"\n          - \"        # If Isapginated is 0, then run the query and dump its out-put in the file specified\"\n          - \"        # using try and catch to catch the error\"\n          - \"        try\"\n          - \"        {\"\n          - \"            $result = Invoke-Sqlcmd -ServerInstance $InstanceName -Query $Query -ErrorAction Stop -QueryTimeout $Timeout\"\n          - \"            $result | Export-Csv -NoTypeInformation -Path $Filename -Append -Encoding UTF8\"\n          - \"        }\"\n          - \"        catch\"\n          - \"        {\"\n          - \"            Write-Error  $_.Exception.Message\"\n          - \"        }\"\n          - \"        return\"\n          - \"    }\"\n          - \"    $PageNo = 1\"\n          - \"    do\"\n          - \"    {\"\n          - \"        # If paginated then, fetch result until we receive zero rows from the SQL server\"\n          - \"        $Offset = ($PageNo - 1) * $Limit\"\n          - \"        # constructing the pagination variable\"\n          - \"        $PaginationParams = @(\"\n          - \"        \\\"Offset='$Offset'\\\",\"\n          - \"        \\\"limit='$Limit'\\\"\"\n          - \"        )\"\n          - \"        try\"\n          - \"        {\"\n          - \"            $result = Invoke-Sqlcmd -ServerInstance $InstanceName -Query $Query -ErrorAction Stop -Variable $PaginationParams -QueryTimeout $Timeout\"\n          - \"            $result | Export-Csv -NoTypeInformation -Path $Filename -Append -Encoding UTF8\"\n          - \"        }\"\n          - \"        catch\"\n          - \"        {\"\n          - \"            Write-Error  $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        # incrementing page number\"\n          - \"        $PageNo += 1\"\n          - \"    } while (@($result).count -gt 0)\"\n          - \"}\"\n          - \"\"\n          - \"# Get-StandaloneDBs dumps stand alone database present inside the sql server, it fetches standalone database\"\n          - \"# in paginated fashion\"\n          - \"# name = name of the database\"\n          - \"# compatibility_level = 150, 140, 130 according to the sql server verison\"\n          - \"# state -> dictates database state, i.e. online offiline, restoring, returns int 1,2,3\"\n          - \"# recovery_model -> dictates recovery model of the database, 1 -> SIMPLE recovery model, 2 -> BULK recovery model,\"\n          - \"#  3 -> FULL recovery model\"\n          - \"# database_id is the integer database id\"\n          - \"# database_size is the database size, it is in KBs\"\n          - \"# database_guid is the database guid of the database\"\n          - \"# instance_version is the product version of the instance\"\n          - \"function Get-StandaloneDBs\"\n          - \"{\"\n          - \"    param($InstanceName, $FilenamePrefix, $Limit, $Timeout)\"\n          - \"\"\n          - \"    # query to fetch standalone databases. First, it uses pagination to fetch a subset of the database,\"\n          - \"    # then apply group by on sys.master_files on database_id to get the size of the database,\"\n          - \"    # using above generated tables use apply join on database_recovery_status to get the database details\"\n          - \"    $StandaloneDBQuery = \\\"\"\n          - \"                            ;\"\n          - \"                            WITH paginated_databases AS\"\n          - \"                            (\"\n          - \"                                     SELECT   d.name,\"\n          - \"                                              d.compatibility_level,\"\n          - \"                                              d.state,\"\n          - \"                                              d.recovery_model,\"\n          - \"                                              CONVERT(NVARCHAR, d.create_date, 127) AS create_date,\"\n          - \"                                              d.database_id,\"\n          - \"                                              CASE\"\n          - \"                                                    WHEN d.is_read_only = 1 Then 1\"\n          - \"                                                    ELSE 0\"\n          - \"                                              END as 'is_read_only',\"\n          - \"                                              d.source_database_id\"\n          - \"                                     FROM     sys.databases AS d\"\n          - \"                                     where NOT EXISTS (SELECT * FROM sys.availability_databases_cluster as adc\"\n          - \"                                                WHERE\"\n          - \"                                                adc.database_name = d.name)\"\n          - \"                                     ORDER BY d.database_id\"\n          - \"                                     OFFSET CONVERT(int, `$(offset) ) rows\"\n          - \"                                     FETCH next CONVERT( int, `$(limit) ) rows only ), db_size AS\"\n          - \"                            (\"\n          - \"                                     SELECT   pd.database_id,\"\n          - \"                                              CONVERT(varchar,sum(cast(mf.size as BIGINT))*8) AS database_size,\"\n          - \"                                              CONVERT(varchar,sum(cast(mf.filestream_enabled as BIGINT))) AS filestream_enabled\"\n          - \"                                     FROM     paginated_databases             AS pd\"\n          - \"                                     JOIN\"\n          - \"                                     (\"\n          - \"                                         SELECT mfs.size as size,\"\n          - \"                                                mfs.database_id,\"\n          - \"                                                CASE\"\n          - \"                                                    WHEN mfs.type = 2 Then 1\"\n          - \"                                                    ELSE 0\"\n          - \"                                                END as 'filestream_enabled'\"\n          - \"                                        from sys.master_files mfs\"\n          - \"                                     ) as mf\"\n          - \"                                     ON       pd.database_id=mf.database_id\"\n          - \"                                     GROUP BY pd.database_id\"\n          - \"                            )\"\n          - \"                            SELECT\"\n          - \"                                   ROW_NUMBER() OVER(ORDER BY (SELECT 1)) + `$(offset) AS table_index,\"\n          - \"                                   pd.name,\"\n          - \"                                   pd.compatibility_level,\"\n          - \"                                   pd.state,\"\n          - \"                                   pd.recovery_model,\"\n          - \"                                   pd.create_date,\"\n          - \"                                   pd.database_id,\"\n          - \"                                   drs.database_guid,\"\n          - \"                                   db_size.database_size,\"\n          - \"                                   serverproperty('productversion') AS instance_version,\"\n          - \"                                   pd.is_read_only,\"\n          - \"                                   db_size.filestream_enabled,\"\n          - \"                                   pd.source_database_id\"\n          - \"                            FROM   paginated_databases pd\"\n          - \"                            JOIN   sys.database_recovery_status drs\"\n          - \"                            ON     pd.database_id = drs.database_id\"\n          - \"                            JOIN   db_size\"\n          - \"                            ON     db_size.database_id = pd.database_id;\"\n          - \"                        \\\"\"\n          - \"    # construct csv file name\"\n          - \"    $FileName = $FilenamePrefix + '_standalone_database.csv'\"\n          - \"    Invoke-SQLQuery $InstanceName $StandaloneDBQuery $FileName $Limit 1 $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"# Get-AGDatabase dumps AG database present inside the SQL server; it fetches AGDBs in a paginated fashion\"\n          - \"# name = name of the database\"\n          - \"# compatibility_level = 150, 140, 130 according to the SQL server version\"\n          - \"# state -> dictates database state, i.e. online offline, restoring, returns int 1,2,3\"\n          - \"# recovery_model -> dictates recovery model of the database\"\n          - \"# database_id is the integer database id\"\n          - \"# database_size is the database size; it is in KBs\"\n          - \"# database_guid is the database guid of the database\"\n          - \"# instance_version is the product version of the instance\"\n          - \"# group_database_id is AG database guid which will serve as database guid\"\n          - \"# group_id is the AG guid, which is the native id for the AG\"\n          - \"function Get-AGDatabase\"\n          - \"{\"\n          - \"    param($InstanceName, $FilenamePrefix, $Limit, $Timeout)\"\n          - \"    # query to fetch AG databases. First, it uses pagination to fetch a subset of the database, then applies group by\"\n          - \"    # on sys.master_files on database_id to get the size of the database, using above generated tables,\"\n          - \"    # apply left join on availability_databases_cluster and dm_hadr_availability_group_states tables to\"\n          - \"    # get the AG database details\"\n          - \"    $AGDatabaseQuery = \\\"\"\n          - \"                        ;\"\n          - \"                        WITH paginated_databases AS\"\n          - \"                        (\"\n          - \"                                 SELECT   d.name,\"\n          - \"                                          d.compatibility_level,\"\n          - \"                                          d.state,\"\n          - \"                                          d.recovery_model,\"\n          - \"                                          CONVERT(NVARCHAR, d.create_date, 127) AS create_date,\"\n          - \"                                          d.database_id,\"\n          - \"                                          d.group_database_id,\"\n          - \"                                          CASE\"\n          - \"                                                WHEN d.is_read_only = 1 Then 1\"\n          - \"                                                ELSE 0\"\n          - \"                                          END as 'is_read_only'\"\n          - \"                                 FROM     sys.databases AS d\"\n          - \"                                 where EXISTS (SELECT * FROM sys.availability_databases_cluster as adc\"\n          - \"                                                WHERE\"\n          - \"                                                adc.database_name = d.name)\"\n          - \"                                 ORDER BY d.database_id\"\n          - \"                                 OFFSET CONVERT(int, `$(offset) ) rows\"\n          - \"                                 FETCH next CONVERT( int, `$(limit) ) rows only ),\"\n          - \"                         db_size AS\"\n          - \"                        (\"\n          - \"                                 SELECT   pd.database_id,\"\n          - \"                                          CONVERT(varchar,sum(cast(mf.size as BIGINT))*8) AS database_size,\"\n          - \"                                          CONVERT(varchar,sum(cast(mf.filestream_enabled as BIGINT))) AS filestream_enabled\"\n          - \"                                 FROM     paginated_databases             AS pd\"\n          - \"                                                                      JOIN\"\n          - \"                                     (\"\n          - \"                                         SELECT mfs.size as size,\"\n          - \"                                                mfs.database_id,\"\n          - \"                                                CASE\"\n          - \"                                                    WHEN mfs.type = 2 Then 1\"\n          - \"                                                    ELSE 0\"\n          - \"                                                END as 'filestream_enabled'\"\n          - \"                                        from sys.master_files mfs\"\n          - \"                                     ) as mf\"\n          - \"                                 ON       pd.database_id=mf.database_id\"\n          - \"                                 GROUP BY pd.database_id )\"\n          - \"                        SELECT\"\n          - \"                                  ROW_NUMBER() OVER(ORDER BY (SELECT 1)) + `$(offset) AS table_index,\"\n          - \"                                  CASE\"\n          - \"                                            WHEN ags.primary_replica =Serverproperty('ServerName')  THEN 1\"\n          - \"                                            ELSE 0\"\n          - \"                                  END AS 'from_primary_replica',\"\n          - \"                                  d.name,\"\n          - \"                                  d.compatibility_level,\"\n          - \"                                  d.state,\"\n          - \"                                  d.recovery_model,\"\n          - \"                                  d.create_date,\"\n          - \"                                  d.database_id,\"\n          - \"                                  db_size.database_size,\"\n          - \"                                  serverproperty('productversion') AS instance_version,\"\n          - \"                                  adc.group_database_id,\"\n          - \"                                  adc.group_id,\"\n          - \"                                  d.is_read_only,\"\n          - \"                                  db_size.filestream_enabled,\"\n          - \"                                  db_replica_state.synchronization_state\"\n          - \"                        FROM      paginated_databases d\"\n          - \"                        JOIN      db_size\"\n          - \"                        ON        db_size.database_id = d.database_id\"\n          - \"                        LEFT JOIN sys.availability_databases_cluster adc\"\n          - \"                        ON        d.group_database_id = adc.group_database_id\"\n          - \"                        LEFT JOIN sys.dm_hadr_availability_group_states ags\"\n          - \"                        ON        ags.group_id = adc.group_id\"\n          - \"                        LEFT JOIN sys.dm_hadr_database_replica_states db_replica_state\"\n          - \"                        ON        d.group_database_id = db_replica_state.group_database_id\"\n          - \"                        where db_replica_state.is_local = 1;\"\n          - \"                        \\\"\"\n          - \"    # construct csv file name\"\n          - \"    $FileName = $FilenamePrefix + '_a_g_database.csv'\"\n          - \"    Invoke-SQLQuery $InstanceName $AGDatabaseQuery $FileName $Limit 1 $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"# Get-InstanceDetails fetches details related to the specific instance\"\n          - \"# is_a_g_present -> tells if a ag is present inside sql server or not\"\n          - \"# edition -> is the edition of the sql server (Enterprise Edition (64-bit))\"\n          - \"# product_version -> is the product version of the sql server (14.0.1000.169)\"\n          - \"# server_name -> is the server name of the sql instance(AG-S2017-4\\\\AGSQL)\"\n          - \"# instance_name is instance name of the sql server(AGSQL)\"\n          - \"# host_name is host name of the host(AG-S2017-4)\"\n          - \"function Get-InstanceDetails\"\n          - \"{\"\n          - \"    param($InstanceName, $FilenamePrefix, $Timeout)\"\n          - \"    # InstanceQuery query fetches is a ag present in the instance or not, edition(Enterprise Edition (64-bit)),\"\n          - \"    # product version(14.0.1000.169) server_name(hostname\\\\instanceName i.e., AG-S2017-4\\\\AGSQL),\"\n          - \"    # instance name(i.e., AGSQL) and hostName(i.e., AG-S2017-4)\"\n          - \"    # We have an enum IsAGPresent defined in that 1 means ag is not present, and 2 is AG is present\"\n          - \"    $InstanceQuery = \\\"\"\n          - \"                    SELECT 1 AS table_index,\"\n          - \"                           CASE\"\n          - \"                             WHEN EXISTS(\"\n          - \"                                         SELECT 1\"\n          - \"                                         FROM   sys.availability_groups) THEN 1\"\n          - \"                             ELSE 2\"\n          - \"                           END                                           AS 'is_a_g_present',\"\n          - \"                           Serverproperty('Edition')                     AS edition,\"\n          - \"                           Serverproperty('ProductVersion')              AS product_version,\"\n          - \"                           Serverproperty('ServerName')                  AS server_name,\"\n          - \"                           Serverproperty('InstanceName')                AS instance_name,\"\n          - \"                           Serverproperty('ComputerNamePhysicalNetBIOS') AS host_name;\"\n          - \"                    \\\"\"\n          - \"    # construct csv file name\"\n          - \"    $FileName = $FilenamePrefix + '_instance_details.csv'\"\n          - \"    Invoke-SQLQuery $InstanceName $InstanceQuery $FileName 0 0 $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"# Get-AGDetails fetches AG details related to the AG,\"\n          - \"# table_index is the row index\"\n          - \"# from_primary_replica is this entry coming from AG primary replica or not\"\n          - \"# primary_replica is the primary replica name(which is the server name of the SQL instance)\"\n          - \"# replica_id is the replica id of the replica\"\n          - \"# replica_server_name replica server name\"\n          - \"# failover_mode failover mode of the replica\"\n          - \"# synchronization_state is the sync state of the replica(sync state, synchronizing state)\"\n          - \"# availability_mode is the commit mode of the replica (sync commit, async commit)\"\n          - \"# name is the name of the AG\"\n          - \"function Get-AGDetails\"\n          - \"{\"\n          - \"    param($InstanceName, $FilenamePrefix, $Timeout)\"\n          - \"    # AGQuery query fetches details related to the AG. Currently, it is non-paginated because the left joins\"\n          - \"    # even if we paginate, we will gaining much as the max number should not be more than 10\"\n          - \"    $AGQuery = \\\"\"\n          - \"                SELECT\"\n          - \"                           ROW_NUMBER() OVER(ORDER BY (SELECT 1)) AS table_index,\"\n          - \"                           CASE\"\n          - \"                                      WHEN ags.primary_replica = Serverproperty('ServerName')  THEN 1\"\n          - \"                                      ELSE 0\"\n          - \"                           END AS 'from_primary_replica',\"\n          - \"                           ags.primary_replica,\"\n          - \"                           ar.replica_id,\"\n          - \"                           ag.group_id,\"\n          - \"                           ar.replica_server_name,\"\n          - \"                           ar.failover_mode,\"\n          - \"                           '' as synchronization_state,\"\n          - \"                           ag.name,\"\n          - \"                           ar.availability_mode\"\n          - \"                FROM       sys.availability_groups   AS ag\"\n          - \"                INNER JOIN sys.availability_replicas AS ar\"\n          - \"                ON         ag.group_id = ar.group_id\"\n          - \"                LEFT JOIN  sys.dm_hadr_availability_group_states AS ags\"\n          - \"                ON         ag.group_id = ags.group_id\"\n          - \"                \\\"\"\n          - \"\"\n          - \"    $FileName = $FilenamePrefix + '_a_g_details.csv'\"\n          - \"    Invoke-SQLQuery $InstanceName $AGQuery $FileName 0 0 $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"# Get-FCINodes fetches FCI nodes,\"\n          - \"# table_index is the row index\"\n          - \"# node_name is name of a node in the SQL Server failover cluster instance\"\n          - \"# status is status of the node in a SQL Server failover cluster instance:  0, 1, 2, 3, -1. More info can be\"\n          - \"#   found here - https://docs.microsoft.com/en-us/windows/win32/api/clusapi/nf-clusapi-getclusternodestate\"\n          - \"# status_description is description  of the status of the SQL Server failover cluster node.\"\n          - \"# is_current_owner is set to 1 when this node is the current owner of the SQL Server failover cluster resource\"\n          - \"function Get-FCINodes\"\n          - \"{\"\n          - \"    param($InstanceName, $FileNamePrefix, $Timeout)\"\n          - \"    $FCINodeQuery = \\\"\"\n          - \"                SELECT\"\n          - \"                           ROW_NUMBER() OVER(ORDER BY (SELECT 1)) AS table_index,\"\n          - \"                           NodeName as node_name,\"\n          - \"                           status,\"\n          - \"                           status_description,\"\n          - \"                           is_current_owner\"\n          - \"                FROM       sys.dm_os_cluster_nodes;\"\n          - \"    \\\"\"\n          - \"    $FileName = $FileNamePrefix + '_fci_nodes.csv'\"\n          - \"    Invoke-SQLQuery $InstanceName  $FCINodeQuery $FileName 0 0 $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"# Get-InstanceInventory is a function that invokes other functions to get inventory\"\n          - \"function Get-InstanceInventory\"\n          - \"{\"\n          - \"    param($InstanceName, $FilenamePrefix, $Limit, $Timeout)\"\n          - \"    Get-StandaloneDBs $InstanceName $FilenamePrefix $Limit $Timeout\"\n          - \"    Get-AGDatabase $InstanceName $FilenamePrefix $Limit $Timeout\"\n          - \"    Get-AGDetails $InstanceName $FilenamePrefix $Timeout\"\n          - \"    Get-InstanceDetails $InstanceName $FilenamePrefix $Limit $Timeout\"\n          - \"    Get-FCINodes $InstanceName $FilenamePrefix $Timeout\"\n          - \"}\"\n          - \"\"\n          - \"$InstanceName = \\\"{{InstanceName}}\\\"\"\n          - \"$FilenamePrefix = \\\"{{FilenamePrefix}}\\\"\"\n          - \"$Limit = {{Limit}}\"\n          - \"$Timeout = {{Timeout}}\"\n          - \"\"\n          - \"# Get-InstanceInventory fetches inventory for the instance\"\n          - \"Get-InstanceInventory $InstanceName $FilenamePrefix $Limit $Timeout\"\n          - \"\"\n          - \"# example\"\n          - \"# Get-InstanceInventory 'AG-S2017-4\\\\AGSQL' 'C:\\\\Program Files\\\\Clumio\\\\Edge Connector\\\\mssql\\\\inv\\\\check' 5 180\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-InventorySync-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-3"
}

resource "aws_ssm_document" "ssm_document_invoke_ps_script" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"SSM document to run Clumio PowerShell scripts\"\n  parameters:\n    ScriptOpID:\n      type: \"String\"\n      description: \"Operation ID representing the script to be executed\"\n      allowedPattern: \"[0-9]+\"\n    Flags:\n      type: \"String\"\n      description: \"Flags to invoke\"\n      default: \"junk parameter\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"$flags = \\\"{{Flags}}\\\"\"\n          - \"if (\\\"$flags\\\" -eq \\\"junk parameter\\\") {\"\n          - \" $flags = \\\"\\\"\"\n          - \"}\"\n          - \"$binary_path = (Get-ItemProperty -Path 'HKLM:SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment' -name CLUMIO_INSTALL_DIR).CLUMIO_INSTALL_DIR\"\n          - \"$mapping = Get-Content ($binary_path + '\\\\hcm\\\\op_id_to_script_path.json') | Out-String | ConvertFrom-Json\"\n          - \"$script_path = $binary_path + ($mapping.{{ScriptOpID}}).path\"\n          - \"$cmd = $script_path + ' ' + $flags\"\n          - \"Invoke-Expression -Command $cmd\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-InvokePsScript-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-2"
}

resource "aws_ssm_document" "ssm_document_mssql_prereq_heartbeat" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"MSSQL Prereq Heartbeat HCMsrv\"\n  parameters:\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Load-Module will load the $name module if it is not already loaded. Will return false, if there is error in\"\n          - \"# loading the module. Else, return true.\"\n          - \"function Load-Module\"\n          - \"{\"\n          - \"    param (\"\n          - \"        [parameter(Mandatory = $true)][string] $name\"\n          - \"    )\"\n          - \"    $retVal = $true\"\n          - \"    if (!(Get-Module -Name $name))\"\n          - \"    {\"\n          - \"        $retVal = Get-Module -ListAvailable | where { $_.Name -eq $name }\"\n          - \"        if ($retVal)\"\n          - \"        {\"\n          - \"            try\"\n          - \"            {\"\n          - \"                Import-Module $name -ErrorAction SilentlyContinue\"\n          - \"            }\"\n          - \"            catch\"\n          - \"            {\"\n          - \"                $retVal = $false\"\n          - \"            }\"\n          - \"        }\"\n          - \"    }\"\n          - \"    return $retVal\"\n          - \"}\"\n          - \"\"\n          - \"# GetClusterDetails returns cluster name and id for given sql service.\"\n          - \"# If the sql service is not clustered, it returns empty strings.\"\n          - \"# It uses `Get-ClusterResource` command to list all the clustered SQL instances and then find name and id.\"\n          - \"function GetClusterDetails {\"\n          - \"    param (\"\n          - \"        [parameter(Mandatory = $true)][string] $serviceName\"\n          - \"    )\"\n          - \"    $clusterName = \\\"\\\"\"\n          - \"    $clusterId = \\\"\\\"\"\n          - \"    # Get-ClusterResource will not work if FailoverClusters module is not loaded\"\n          - \"    if (Load-Module \\\"FailoverClusters\\\")\"\n          - \"    {\"\n          - \"        try {\"\n          - \"            $get_cluster_resource = Get-ClusterResource -ErrorAction Stop  -WarningAction silentlyContinue\"\n          - \"        }\"\n          - \"        catch {\"\n          - \"            return $clusterName, $clusterId\"\n          - \"        }\"\n          - \"        try\"\n          - \"        {\"\n          - \"            # Check if the current service is default service or not\"\n          - \"            if ($serviceName -eq \\\"MSSQLSERVER\\\")\"\n          - \"            {\"\n          - \"                # Get clusterResource for given SQL Server instance\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object {$_.Name -eq \\\"SQL Server\\\"})\"\n          - \"            }\"\n          - \"            else {\"\n          - \"                # The INSTANCE_NAME part is extracted from the service name\"\n          - \"                # The serviceName is of the format MSSQL$INSTANCE_NAME, in order to fetch the\"\n          - \"                # instance name, service Name is split with respect to $\"\n          - \"                $instance_name = $serviceName.Split('$')[1]\"\n          - \"                # Get clusterResource for given SQL Server instance\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object {$_.Name -eq \\\"SQL Server ($instance_name)\\\"})\"\n          - \"            }\"\n          - \"\"\n          - \"            # If clusterResource is empty, it means the current sql service is not clustered.\"\n          - \"            if ($clusterResource -ne $null)\"\n          - \"            {\"\n          - \"                $requiredGroup = $clusterResource.OwnerGroup\"\n          - \"\"\n          - \"                # $requiredGroup stores ownerGroup of SQL Server resource for given SQL service. The cluster resource\"\n          - \"                # for SQL Network Name for given SQL service will also have same ownerGroup. Use this to find the\"\n          - \"                # corresponsing SQL Network Name resource. We can get further info about cluster from that\"\n          - \"                # SQL Network Name resource\"\n          - \"                $clusterResource = ($get_cluster_resource | Where-Object { $_.ResourceType -eq \\\"Network Name\\\" -and $_.OwnerGroup -eq $requiredGroup })\"\n          - \"                if ($clusterResource -ne $null){\"\n          - \"                    $clusterName = ($clusterResource | Get-ClusterParameter -Name 'Name').Value\"\n          - \"                    $clusterId = $clusterResource.ID\"\n          - \"                }\"\n          - \"            }\"\n          - \"        }\"\n          - \"        catch\"\n          - \"        {\"\n          - \"            Write-Error  $_.Exception.Message\"\n          - \"        }\"\n          - \"    }\"\n          - \"    return $clusterName, $clusterId\"\n          - \"}\"\n\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"# Powershell script for getting all services installed inside a host\"\n          - \"$vars = @(\"\n          - \"\\\"user='$user'\\\"\"\n          - \")\"\n          - \"# checking for the current user\"\n          - \"$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name\"\n          - \"$services = (Get-Service -DisplayName \\\"SQL Server (*\\\")\"\n          - \"$sysadminCheckQuery = \\\"select IS_SRVROLEMEMBER('sysadmin') as perm\\\"\"\n          - \"$SqlWriterSYSAdminCheckQuery = \\\"select IS_SRVROLEMEMBER('sysadmin', 'NT SERVICE\\\\SQLWriter') as perm\\\"\"\n          - \"$service_info = @()\"\n          - \"$hostName = $env:computername\"\n          - \"$errorOuccered = $false\"\n          - \"\"\n          - \"# check if any sql server is installed or not, if length is zero then no\"\n          - \"# sql server is installed\"\n          - \"if ($services.Length -eq 0)\"\n          - \"{\"\n          - \"    $service_info += @{\"\n          - \"        name = 'SQL_SERVER_INSTALLED'\"\n          - \"        status = \\\"SQL_SERVER_NOT_FOUND\\\"\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"    $errorOuccered = $true\"\n          - \"    Write-Error \\\"no sql sever installed\\\"\"\n          - \"    return $service_info\"\n          - \"} else {\"\n          - \"    $service_info += @{\"\n          - \"        name = 'SQL_SERVER_INSTALLED'\"\n          - \"        status = \\\"SQL_SERVER_FOUND\\\"\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"}\"\n          - \"\"\n          - \"# loop over every service and fetch information and dump it\"\n          - \"foreach ($service in $services)\"\n          - \"{\"\n          - \"    $serviceStatue = $service.Status.value__\"\n          - \"    if ($serviceStatue -ne 4)\"\n          - \"    {\"\n          - \"        continue\"\n          - \"    }\"\n          - \"    $instanceName = $service.ServiceName\"\n          - \"    $serverName = $hostName\"\n          - \"\"\n          - \"    # GetClusterDetails is defined in fci_utils.ps1. Need to include content of utils.ps1 for running this script.\"\n          - \"    $clusterName, $clusterId = GetClusterDetails $service.ServiceName\"\n          - \"    if ($clusterName -ne \\\"\\\"){\"\n          - \"        $serverName = $clusterName\"\n          - \"    }\"\n          - \"\"\n          - \"    if ($instanceName -ne \\\"MSSQLSERVER\\\")\"\n          - \"    {\"\n          - \"        $instanceName = $service.ServiceName.substring(6)\"\n          - \"        $serverName = $serverName + \\\"\\\\\\\" + $instanceName\"\n          - \"    }\"\n          - \"\"\n          - \"    # first check for sysadmin prev for current user\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $result = Invoke-Sqlcmd -ServerInstance $serverName -Query $sysadminCheckQuery -ErrorAction Stop -Variable $vars\"\n          - \"        if ($result.perm -ne 1)\"\n          - \"        {\"\n          - \"            $service_info += @{\"\n          - \"                name = $serverName\"\n          - \"                status = \\\"SYSADMIN_NOT_PROVISIONED\\\"\"\n          - \"            } | ConvertTo-Json | Out-String\"\n          - \"            $errorOuccered = $true\"\n          - \"            write-error \\\"sys admin permission not given to $serverName\\\"\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            $service_info += @{\"\n          - \"                name = $serverName\"\n          - \"                status = \\\"SYSADMIN_PROVISIONED\\\"\"\n          - \"            } | ConvertTo-Json | Out-String\"\n          - \"        }\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        $service_info += @{\"\n          - \"            name = $serverName\"\n          - \"            status = \\\"SYSADMIN_NOT_PROVISIONED\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered = $true\"\n          - \"        write-Error  $_\"\n          - \"        # throw is terminating command else write-Error is not\"\n          - \"    }\"\n          - \"\"\n          - \"    # Then check if sql writer has sysadmin prev or not\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $result = Invoke-Sqlcmd -ServerInstance $serverName -Query $SqlWriterSYSAdminCheckQuery -ErrorAction Stop\"\n          - \"        if ($result.perm -ne 1)\"\n          - \"        {\"\n          - \"            $service_info += @{\"\n          - \"                name = $serverName\"\n          - \"                status = \\\"SQL_WRITER_SYS_ADMIN_NOT_PROVISIONED\\\"\"\n          - \"            } | ConvertTo-Json | Out-String\"\n          - \"            $errorOuccered = $true\"\n          - \"            write-error \\\"sql writer doesn't have sys admin permission not given to $serverName\\\"\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            $service_info += @{\"\n          - \"                name = $serverName\"\n          - \"                status = \\\"SQL_WRITER_SYS_ADMIN_PROVISIONED\\\"\"\n          - \"            } | ConvertTo-Json | Out-String\"\n          - \"        }\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        $errorOuccered = $true\"\n          - \"        $service_info += @{\"\n          - \"            name = $serverName\"\n          - \"            status = \\\"SQL_WRITER_SYS_ADMIN_NOT_PROVISIONED\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        write-Error $_\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"# refs:\"\n          - \"# https://powershellshocked.wordpress.com/2018/04/27/checking-the-state-of-vss-writers/\"\n          - \"# https://social.technet.microsoft.com/Forums/en-US/349427e7-22ff-49ce-aa11-73d5b878c0ce/\"\n          - \"# using-invokecommand-to-run-vssadmin-list-writers-on-several-servers-how-do-i-sort-the-results\"\n          - \"# NOTE: this check is added in script but it is not function as this check usually takes\"\n          - \"# time if writer is busy\"\n          - \"# Check-VSSListSqlWriterPresent checks if sql writer is present or not if not present\"\n          - \"# then throw error\"\n          - \"function Check-VSSListSqlWriterPresent {\"\n          - \"    $plaintext = vssadmin list writers\"\n          - \"    $vsswriters = @()\"\n          - \"    foreach ($line in $plaintext) {\"\n          - \"        switch -regex ($line) {\"\n          - \"            (\\\"^Writer name:\\\") {\"\n          - \"                $vsswriters += $Obj\"\n          - \"                Remove-Variable -name Obj -Force -ErrorAction 0\"\n          - \"\"\n          - \"                $Obj = New-Object System.Object\"\n          - \"                $writername = ($line -split \\\": \\\")[1] -replace \\\"'\\\", \\\"Failed\\\"\"\n          - \"                $Obj | Add-Member -MemberType NoteProperty -Name \\\"WriterName\\\" -value $writername -Force\"\n          - \"                Remove-Variable -Name writername -force -ErrorAction 0\"\n          - \"                break;\"\n          - \"            }\"\n          - \"            (\\\"^   \\\") {\"\n          - \"                $attrname = ($line -split \\\": \\\")[0] -Replace \\\"   \\\", \\\"Failed\\\"\"\n          - \"                $attrval = ($line -split \\\": \\\")[1] -replace \\\"'\\\", \\\"Failed\\\"\"\n          - \"                $Obj | Add-Member -MemberType NoteProperty -Name $attrname -value $attrval -Force\"\n          - \"                Remove-Variable -Name attrname, attrval -Force -ErrorAction 0\"\n          - \"                break;\"\n          - \"            }\"\n          - \"            default {\"\n          - \"                Continue\"\n          - \"            }\"\n          - \"        }\"\n          - \"    }\"\n          - \"    $sqlWriterObj = $vsswriters | Where-Object WriterName -Contains 'SqlServerWriter'\"\n          - \"\"\n          - \"    if ($sqlWriterObj.Length -eq 0) {\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_VSS_LIST_WRITER'\"\n          - \"            status = \\\"SQL_VSS_LIST_WRITER_NOT_FOUND\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        Write-Error \\\"sql writer not found\\\"\"\n          - \"    } else {\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_VSS_LIST_WRITER'\"\n          - \"            status = \\\"SQL_VSS_LIST_WRITER_FOUND\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"# CheckVssWriterService-Running checks if vss writer service is running or not, if not\"\n          - \"# running then throw error\"\n          - \"function CheckVssWriterServiceRunning {\"\n          - \"    param([ref] $errorOuccered)\"\n          - \"    try {\"\n          - \"        $vssWriterService = (Get-Service -DisplayName \\\"SQL Server VSS Writer*\\\")\"\n          - \"    }\"\n          - \"    catch{\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_SERVER_VSS_WRITER_SERVICE'\"\n          - \"            status = \\\"SQL_SERVER_VSS_WRITER_SERVICE_NOT_FOUND\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered.Value = $true\"\n          - \"        return $service_info\"\n          - \"    }\"\n          - \"\"\n          - \"    #check for the length of the vssWriterService object, it should be one only\"\n          - \"    if ($vssWriterService.Length -ne 1)\"\n          - \"    {\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_SERVER_VSS_WRITER_SERVICE'\"\n          - \"            status = \\\"SQL_SERVER_VSS_WRITER_SERVICE_NOT_FOUND\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered.Value = $true\"\n          - \"        Write-Error \\\"vss writer service not present\\\"\"\n          - \"        return $service_info\"\n          - \"    }\"\n          - \"    $service_info += @{\"\n          - \"        name = 'SQL_SERVER_VSS_WRITER_SERVICE'\"\n          - \"        status = \\\"SQL_SERVER_VSS_WRITER_SERVICE_FOUND\\\"\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"\"\n          - \"\"\n          - \"    # checks running state of the vss service, 4 prepresent running state\"\n          - \"    $serviceStatus = $vssWriterService.Status.value__\"\n          - \"    if ($serviceStatus -ne 4)\"\n          - \"    {\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_SERVER_VSS_WRITER_SERVICE'\"\n          - \"            status = \\\"SQL_SERVER_VSS_WRITER_SERVICE_NOT_RUNNING\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered.Value = $true\"\n          - \"        Write-Error \\\"sql server vss writer service not running\\\"\"\n          - \"        return $service_info\"\n          - \"    }\"\n          - \"    $service_info += @{\"\n          - \"        name = 'SQL_SERVER_VSS_WRITER_SERVICE'\"\n          - \"        status = \\\"SQL_SERVER_VSS_WRITER_SERVICE_RUNNING\\\"\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"    return $service_info\"\n          - \"}\"\n          - \"\"\n          - \"# CheckVSSServicePresent checks if vss service is not present or not\"\n          - \"function CheckVSSServicePresent\"\n          - \"{\"\n          - \"    param ([ref] $errorOuccered)\"\n          - \"    # fetch vss shadow copy service\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $vssWriterService = (Get-Service -DisplayName \\\"Volume Shadow Copy*\\\")\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        # if error out then update SQL_SERVER_VSS_SHADOW_SERVICE status as\"\n          - \"        # SQL_SERVER_VSS_SHADOW_SERVICE_NOT_PRESENT\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_SERVER_VSS_SHADOW_SERVICE'\"\n          - \"            status = \\\"SQL_SERVER_VSS_SHADOW_SERVICE_NOT_PRESENT\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered.Value = $true\"\n          - \"        Write-Error \\\"vss shadow service not present\\\"\"\n          - \"        return $service_info\"\n          - \"    }\"\n          - \"\"\n          - \"    # check for length if length is zero then there is no shadow service to take\"\n          - \"    # vss shadow copy\"\n          - \"    if ($vssWriterService.Length -eq 0)\"\n          - \"    {\"\n          - \"        $service_info += @{\"\n          - \"            name = 'SQL_SERVER_VSS_SHADOW_SERVICE'\"\n          - \"            status = \\\"SQL_SERVER_VSS_SHADOW_SERVICE_NOT_PRESENT\\\"\"\n          - \"        } | ConvertTo-Json | Out-String\"\n          - \"        $errorOuccered.Value = $true\"\n          - \"        Write-Error \\\"vss shadow service not present\\\"\"\n          - \"        return $service_info\"\n          - \"    }\"\n          - \"\"\n          - \"    $service_info += @{\"\n          - \"        name = 'SQL_SERVER_VSS_SHADOW_SERVICE'\"\n          - \"        status = \\\"SQL_SERVER_VSS_SHADOW_SERVICE_PRESENT\\\"\"\n          - \"    } | ConvertTo-Json | Out-String\"\n          - \"    return $service_info\"\n          - \"}\"\n          - \"\"\n          - \"\"\n          - \"# Check-VSSListSqlWriterPresent takes a lot of time if writer is busy\"\n          - \"# Check-VSSListSqlWriterPresent please don't un-comment requires sys admin prev\"\n          - \"$service_info += CheckVssWriterServiceRunning ([ref] $errorOuccered)\"\n          - \"$service_info += CheckVSSServicePresent ([ref] $errorOuccered)\"\n          - \"\"\n          - \"# If there is error at any place of code then print srvice into as error stirng else\"\n          - \"# in output strint\"\n          - \"if ($errorOuccered -eq $true) {\"\n          - \"    Write-Error ($service_info | Out-String)\"\n          - \"} else {\"\n          - \"    # printout $service_info for debugging\"\n          - \"    $service_info\"\n          - \"}\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-MSSQLPreREQ-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_normal_heartbeat" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Normal Heartbeat HCMsrv\"\n  parameters:\n    EC2VersionsFileName:\n      type: \"String\"\n      description: \"Version file name\"\n    EC2HostServiceName:\n      type: \"String\"\n      description: \"The name of the service to be installed\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# Powershell script for normal heartbeat for an ec2 host\"\n          - \"# The output of this file is parsed based on new line to get the current binaries version\"\n          - \"# installed on the ec2 host. So any change in this file should also reflect in parsing logic\"\n          - \"#>\"\n          - \"Function NormalHBEC2Host {\"\n          - \"    Param ($EC2VersionsFileName, $EC2HostServiceName)\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $versionFilePath = \\\"$env:ProgramData//clumio//$EC2VersionsFileName\\\"\"\n          - \"        $VersionPathExists = Test-Path $VersionFilePath\"\n          - \"        if (!$VersionPathExists)\"\n          - \"        {\"\n          - \"            Write-host \\\"version file does not exists on host $VersionFilePath\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"        }\"\n          - \"        # Fetch the binaries version on the host\"\n          - \"        $currVersion = Get-Content $versionFilePath\"\n          - \"        Write-Host \\\"current binaries version is - $currVersion\\\"\"\n          - \"        $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"        # If CJ tracker service is not running, Try to restart the service. If we fail to restart\"\n          - \"        # the service then return error\"\n          - \"        if ($serviceStatus.Status -ne \\\"Running\\\") {\"\n          - \"            # NOTE: Start-Service runs in a synchronous manner\"\n          - \"            # https://stackoverflow.com/questions/34309023/does-restart-service-run-asynchronously\"\n          - \"            Start-Service $EC2HostServiceName\"\n          - \"            $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"            if ($serviceStatus.Status -ne \\\"Running\\\") {\"\n          - \"                Write-host \\\"clumio services on ec2 host are not running $EC2HostServiceName\\\"\"\n          - \"                Write-Error $_.Exception.Message\"\n          - \"            }\"\n          - \"        }\"\n          - \"        $hostName = $env:computername\"\n          - \"        Write-host \\\"host name is - $hostName\\\"\"\n          - \"    }\"\n          - \"    catch {\"\n          - \"        Write-host \\\"got error in normal heartbeat on host\\\"\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"    Write-host \\\"normal HB completed successfully\\\"\"\n          - \"}\"\n          - \"\"\n          - \"# reading object related variable\"\n          - \"# Version File Path\"\n          - \"$EC2VersionsFileName = '{{EC2VersionsFileName}}'\"\n          - \"# EC2 Host Service Name\"\n          - \"$EC2HostServiceName = '{{EC2HostServiceName}}'\"\n          - \"\"\n          - \"NormalHBEC2Host $EC2VersionsFileName $EC2HostServiceName\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-NormalHeartbeat-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_remove_old_inventory_files" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Removes old Inventory files\"\n  parameters:\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"$temp_path = (Get-ItemProperty -Path 'HKLM:SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment' -name CLUMIO_TEMP_DIR).CLUMIO_TEMP_DIR\"\n          - \"$temp_path = $temp_path + '\\\\mssql\\\\inv\\\\'\"\n          - \"Get-ChildItem \u2013Path $temp_path -Recurse -Exclude *.ps1 | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-2))} | Remove-Item\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-RemoveOldInventoryFiles-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-3"
}

resource "aws_ssm_document" "ssm_document_ssm_check_heartbeat" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"SSM Prereq HCMsrv\"\n  parameters:\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"$env:computername\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-SSMPreReq-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_system_heartbeat" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"System Heartbeat HCMsrv\"\n  parameters:\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2021 Clumio All Rights Reserved\"\n          - \"# Powershell script for system heartbeat for an ec2 host\"\n          - \"Function SystemHBEC2Host {\"\n          - \"    Param()\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $diskStats = Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property DeviceID, VolumeName, @{ Label = 'FreeSpace (Gb)'; expression = { ($_.FreeSpace/1GB).ToString('F2') } }, @{ Label = 'Total (Gb)'; expression = { ($_.Size/1GB).ToString('F2') } }, @{ label = 'FreePercent'; expression = { [Math]::Round(($_.freespace / $_.size) * 100, 2) } }| ConvertTo-Json\"\n          - \"        $processorInfo = Get-WmiObject  Win32_processor | Select-Object -Property Name, Family, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | ConvertTo-Json\"\n          - \"        $networkInfo = Get-NetAdapter -Name * -Physical | Select-Object -Property \\\"Name\\\", \\\"InterfaceDescription\\\", \\\"InterfaceName\\\", \\\"ifIndex\\\", \\\"Status\\\", \\\"MacAddress\\\", \\\"LinkSpeed\\\" | ConvertTo-Json\"\n          - \"        $osName =  (Get-WMIObject win32_operatingsystem).Caption | out-string\"\n          - \"        $osName = $osName -replace \\\"`t|`n|`r\\\",\\\"\\\"\"\n          - \"        $osArch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture | out-string\"\n          - \"        $osArch =  $osArch -replace \\\"`t|`n|`r\\\",\\\"\\\"\"\n          - \"        $buildNum = (Get-WmiObject Win32_OperatingSystem).BuildNumber\"\n          - \"        $osDetails = @\\\"\"\n          - \"{\"\n          - \"    \\\"OsName\\\":\\\"$osName\\\",\"\n          - \"    \\\"OsVersion\\\":\\\"$osArch\\\",\"\n          - \"    \\\"OsBuild\\\": $buildNum\"\n          - \"}\"\n          - \"\\\"@\"\n          - \"        $totalRam = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum\"\n          - \"        $freePhysicalMem = (Get-Ciminstance Win32_OperatingSystem).FreePhysicalMemory\"\n          - \"        $systemDetails = @\\\"\"\n          - \"{\"\n          - \" \\\"MemoryCapacity\\\": $totalRam,\"\n          - \" \\\"MemoryUsed\\\": $freePhysicalMem,\"\n          - \" \\\"DiskCapacity\\\": $diskStats,\"\n          - \" \\\"ProcessorDetails\\\": $processorInfo,\"\n          - \" \\\"NetworkDetails\\\": $networkInfo,\"\n          - \" \\\"OsDetails\\\": $osDetails\"\n          - \"}\"\n          - \"\\\"@\"\n          - \"        write-output $systemDetails\"\n          - \"    }\"\n          - \"    catch {\"\n          - \"        Write-host \\\"got error in system heartbeat on host\\\"\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"SystemHBEC2Host\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-SystemHeartbeat-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-1"
}

resource "aws_ssm_document" "ssm_document_upgrade_mssql_binaries" {
  content         = "  schemaVersion: \"2.2\"\n  description: \"Script to upgrade clumio binaries\"\n  parameters:\n    S3BucketName:\n      type: \"String\"\n      description: \"S3 bucket to download clumio zip\"\n    S3BucketKey:\n      type: \"String\"\n      description: \"S3 key to download clumio zip\"\n    BinariesFilePath:\n      type: \"String\"\n      description: \"The path for ec2 host binaries\"\n    EC2HostBinaryPath:\n      type: \"String\"\n      description: \"Path to install executables\"\n    EC2HostServiceName:\n      type: \"String\"\n      description: \"The name of the service to be installed\"\n    EC2HostDisplayName:\n      type: \"String\"\n      description: \"The display name of the service to be installed\"\n    EC2HostServiceDescription:\n      type: \"String\"\n      description: \"The description of the service to be installed\"\n    EC2HostServicePath:\n      type: \"String\"\n      description: \"Service installation path\"\n    EC2HostSrcFileDir:\n      type: \"String\"\n      description: \"The current directory which needs to be upgraded\"\n    EC2HostDestinationFileDir:\n      type: \"String\"\n      description: \"The directory from which the upgrade needs to happen\"\n    EC2BinariesVersion:\n      type: \"String\"\n      description: \"Version for the biaries to be installed\"\n    EC2VersionsFileName:\n      type: \"String\"\n      description: \"Version file name\"\n    EC2ProgramDataDir:\n      type: \"String\"\n      description: \"Directory to store version info\"\n    EC2BinariesZipCheckSum:\n      type: \"String\"\n      description: \"EC2 Binaries Zip Checksum\"\n    S3ZipUrl:\n      type: \"String\"\n      description: \"S3 Zip Url\"\n    AWSPSEnabled:\n      type: \"String\"\n      description: \"Boolean flag to use AWS powershell module for download\"\n    executionTimeout:\n      type: \"String\"\n      description: \"Timeout for the SSM custom documents commands, default is set to 3600\"\n      default: \"3600\"\n      allowedPattern: \"[0-9]+\"\n  mainSteps:\n    - action: aws:runPowerShellScript\n      precondition:\n        StringEquals:\n          - platformType\n          - Windows\n      name: runCommands\n      inputs:\n        timeoutSeconds: \"{{executionTimeout}}\"\n        runCommand:\n          - \"# Copyright (c) 2023 Clumio All Rights Reserved\"\n          - \"\"\n          - \"# created exe path, appends version string before the exe in the execuatble name\"\n          - \"function CreateExePath\"\n          - \"{\"\n          - \"    param($raw_exe_path, $version)\"\n          - \"    return $raw_exe_path + '_' + $version + '.exe'\"\n          - \"}\"\n          - \"\"\n          - \"# DeleteOldExecutables deleted the old executable\"\n          - \"# it doesn't delete exe which has current version suffix in it and\"\n          - \"# also doesn't delete cjtracker service\"\n          - \"function DeleteOldExecutables\"\n          - \"{\"\n          - \"    param($EC2HostBinaryPath, $version_numer)\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $paths = @(\"\n          - \"        \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\",\"\n          - \"        \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\",\"\n          - \"        \\\"$EC2HostBinaryPath\\\\hcm\\\"\"\n          - \"        )\"\n          - \"        Get-ChildItem -Path $paths -Attributes !Directory | Where-Object { $_.name -like '*.exe' -and $_.Name -notlike \\\"*$version_numer*\\\" -and $_.Name -notlike \\\"*cjtracker*\\\" } | Remove-Item\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-Host \\\"failed to delete some old files\\\"\"\n          - \"        Write-Host $_.Exception.Message\"\n          - \"    }\"\n          - \"}\"\n          - \"\"\n          - \"# Powershell script for upgrading binaries on ec2 host\"\n          - \"Function UpgradeEC2Binaries\"\n          - \"{\"\n          - \"\"\n          - \"    Param ($S3BucketName, $S3BucketKey, $BinariesFilePath, $EC2HostBinaryPath,\"\n          - \"        $EC2HostServiceName, $EC2HostDisplayName, $EC2HostServiceDescription,\"\n          - \"        $EC2HostServicePath, $EC2HostSrcFileDir, $EC2HostDestinationFileDir,\"\n          - \"        $EC2BinariesVersion, $EC2VersionsFileName, $EC2ProgramDataDir, $EC2BinariesZipCheckSum,\"\n          - \"        $S3ZipUrl, $AWSPSEnabled)\"\n          - \"    try\"\n          - \"    {\"\n          - \"        $version_numer = $EC2BinariesVersion.Replace('.', '_')\"\n          - \"        $BinaryPathExists = Test-Path $EC2HostBinaryPath\"\n          - \"        if (!$BinaryPathExists)\"\n          - \"        {\"\n          - \"            Write-host \\\"binary path does not exists on host $EC2HostBinaryPath\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"\"\n          - \"        # Force powershell to use tls 1.2\"\n          - \"        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\"\n          - \"        if ($AWSPSEnabled -Eq \\\"true\\\")\"\n          - \"        {\"\n          - \"            Copy-S3Object -BucketName $S3BucketName -Key $S3BucketKey -File $BinariesFilePath\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            (New-Object Net.WebClient).DownloadFile($S3ZipUrl, $BinariesFilePath)\"\n          - \"        }\"\n          - \"        Write-host \\\"successfully downloaded file at $BinariesFilePath\\\"\"\n          - \"\"\n          - \"        # check if cjparser service already exists\"\n          - \"        $currService = Get-Service -Name $EC2HostServiceName -ErrorAction Ignore\"\n          - \"        if ($currService.Length -gt 0)\"\n          - \"        {\"\n          - \"            #cjparser service already exists first remove it to upgrade it\"\n          - \"            Stop-Service $EC2HostServiceName -ErrorAction Ignore\"\n          - \"            # Add some delay to stop the running service before removing it\"\n          - \"            Start-Sleep -Seconds 5\"\n          - \"            $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"            if ($serviceStatus.Status -eq \\\"Running\\\")\"\n          - \"            {\"\n          - \"                Write-host \\\"unable to stop the existing service $EC2HostServiceName\\\"\"\n          - \"                Write-Error $_.Exception.Message\"\n          - \"                return\"\n          - \"            }\"\n          - \"            Get-CimInstance -ClassName Win32_Service -Filter \\\"Name='$EC2HostServiceName'\\\" | Remove-CimInstance\"\n          - \"            Write-host \\\"removed existing service $EC2HostServiceName before upgrading it\\\"\"\n          - \"            # Add some delay to remove the existing service from the host before adding it again\"\n          - \"            Start-Sleep -Seconds 10\"\n          - \"        }\"\n          - \"\"\n          - \"        $DownloadZipSHACheckSum = Get-FileHash -Algorithm sha256 $BinariesFilePath\"\n          - \"        if ($DownloadZipSHACheckSum.Hash -ne $EC2BinariesZipCheckSum)\"\n          - \"        {\"\n          - \"            Write-host \\\"checksum mismatched original file hash  $EC2BinariesZipCheckSum download file hash $DownloadZipSHACheckSum\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        $unzipDir = $EC2HostSrcFileDir -replace \\\".{2}$\\\"\"\n          - \"        $PSversion = $PSVersionTable.PSVersion.Major\"\n          - \"        if ($PSversion -ge 5)\"\n          - \"        {\"\n          - \"            Microsoft.PowerShell.Archive\\\\Expand-Archive -LiteralPath $BinariesFilePath -DestinationPath  $unzipDir\"\n          - \"            Write-host \\\"successfully unzipped to $unzipDir\\\"\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            [void](New-Item -Path $unzipDir -ItemType Directory -Force)\"\n          - \"            $Shell = new-object -com Shell.Application\"\n          - \"            $Shell.Namespace($unzipDir).copyhere($Shell.NameSpace($BinariesFilePath).Items(), 0x14)\"\n          - \"            Write-host \\\"successfully unzipped to $unzipDir\\\"\"\n          - \"        }\"\n          - \"\"\n          - \"        Remove-Item $BinariesFilePath -Force -ErrorAction Ignore\"\n          - \"        Write-host \\\"deleted the zip file after unarchive $BinariesFilePath\\\"\"\n          - \"\"\n          - \"        # After unzip is done rename the exes and append the version as the suffix before\"\n          - \"        # coping into the file target destination\"\n          - \"        Rename-Item -Path \\\"$unzipDir\\\\mssql\\\\dp\\\\dpmssqlcloudagent.exe\\\" -NewName (CreateExePath 'dpmssqlcloudagent' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$unzipDir\\\\mssql\\\\dp\\\\uploader.exe\\\" -NewName (CreateExePath 'uploader' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$unzipDir\\\\mssql\\\\dp\\\\restoreagent.exe\\\" -NewName (CreateExePath 'restoreagent' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$unzipDir\\\\hcm\\\\winhostutil.exe\\\" -NewName (CreateExePath 'winhostutil' $version_numer)\"\n          - \"        Rename-Item -Path \\\"$unzipDir\\\\mssql\\\\dp\\\\vss\\\\cvss.exe\\\" -NewName (CreateExePath 'cvss' $version_numer)\"\n          - \"\"\n          - \"        Copy-Item -Path $EC2HostSrcFileDir -Destination $EC2HostDestinationFileDir -Recurse -Force\"\n          - \"        Write-host \\\"Upgraded the binaries and scripts in folder $EC2HostDestinationFileDir\\\"\"\n          - \"\"\n          - \"        Get-ChildItem -Path  $unzipDir -Recurse | Remove-Item -force -recurse\"\n          - \"        Remove-Item $unzipDir -Force\"\n          - \"        Write-host \\\"deleted the source directory after upgrade $unzipDir\\\"\"\n          - \"\"\n          - \"        # create symlinks\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\dpmssqlcloudagent\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\dpmssqlcloudagent\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\uploader\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\uploader\\\" $version_numer)  -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\restoreagent\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\restoreagent\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\hcm\\\\winhostutil\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\hcm\\\\winhostutil\\\" $version_numer)  -Force -ErrorAction Stop\"\n          - \"        New-Item -ItemType SymbolicLink -Path \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\\cvss\\\" -Target (CreateExePath \\\"$EC2HostBinaryPath\\\\mssql\\\\dp\\\\vss\\\\cvss\\\" $version_numer) -Force -ErrorAction Stop\"\n          - \"\"\n          - \"        # update the env variable representing install version\"\n          - \"        [System.Environment]::SetEnvironmentVariable(\\\"CLUMIO_INSTALL_VERSION\\\", $EC2BinariesVersion, 'Machine')\"\n          - \"\"\n          - \"        new-service -Name $EC2HostServiceName -DisplayName $EC2HostDisplayName -Description $EC2HostServiceDescription -BinaryPathName $EC2HostServicePath -StartupType Automatic\"\n          - \"        Write-host \\\"successfully registered service $EC2HostServiceName\\\"\"\n          - \"\"\n          - \"        Start-Service $EC2HostServiceName\"\n          - \"        $serviceStatus = Get-Service -Name $EC2HostServiceName\"\n          - \"        if ($serviceStatus.Status -ne \\\"Running\\\")\"\n          - \"        {\"\n          - \"            Write-host \\\"unable to start the service $EC2HostServiceName\\\"\"\n          - \"            Write-Error $_.Exception.Message\"\n          - \"            return\"\n          - \"        }\"\n          - \"        else\"\n          - \"        {\"\n          - \"            Write-host \\\"successfully started service $EC2HostServiceName\\\"\"\n          - \"        }\"\n          - \"        Set-Content -Path \\\"$env:ProgramData\\\\$EC2ProgramDataDir\\\\$EC2VersionsFileName\\\" -Value $EC2BinariesVersion -Force\"\n          - \"        Write-Host \\\"successfully written the versions info $EC2BinariesVersion in versions directory $env:ProgramData\\\\$EC2ProgramDataDir\\\"\"\n          - \"\"\n          - \"        # delete old exes which are not in use\"\n          - \"        DeleteOldExecutables $EC2HostBinaryPath $version_numer\"\n          - \"\"\n          - \"    }\"\n          - \"    catch\"\n          - \"    {\"\n          - \"        Write-host \\\"got error in upgrading ec2 binaries on host\\\"\"\n          - \"        Write-Error  $_.Exception.Message\"\n          - \"        return\"\n          - \"    }\"\n          - \"    Write-host \\\"successfully upgraded binaries at $BinariesFilePath\\\"\"\n          - \"}\"\n          - \"\"\n          - \"# reading object related variable\"\n          - \"$S3BucketName = '{{S3BucketName}}'\"\n          - \"$S3BucketKey = '{{S3BucketKey}}'\"\n          - \"# BinariesFilePath is the path where s3 object will get downloaded\"\n          - \"$BinariesFilePath = '{{BinariesFilePath}}'\"\n          - \"# EC2HostBinaryPath is the path for ec2 host binaries\"\n          - \"$EC2HostBinaryPath = '{{EC2HostBinaryPath}}'\"\n          - \"# EC2HostServiceName is the name of the service to be upgraded\"\n          - \"$EC2HostServiceName = '{{EC2HostServiceName}}'\"\n          - \"# EC2HostDisplayName is the display name of the service to be upgraded\"\n          - \"$EC2HostDisplayName = '{{EC2HostDisplayName}}'\"\n          - \"# EC2HostServiceDescription is the description of the service to be upgraded\"\n          - \"$EC2HostServiceDescription = '{{EC2HostServiceDescription}}'\"\n          - \"# EC2HostServicePath is the service installation path\"\n          - \"$EC2HostServicePath = '{{EC2HostServicePath}}'\"\n          - \"# EC2HostSrcFileDir is the current directory which needs to be upgraded\"\n          - \"$EC2HostSrcFileDir = '{{EC2HostSrcFileDir}}'\"\n          - \"# EC2HostDestinationFileDir is the directory from which the upgrade needs to happen\"\n          - \"$EC2HostDestinationFileDir = '{{EC2HostDestinationFileDir}}'\"\n          - \"#Version for the biaries to be installed\"\n          - \"$EC2BinariesVersion = '{{EC2BinariesVersion}}'\"\n          - \"#Version file name\"\n          - \"$EC2VersionsFileName = '{{EC2VersionsFileName}}'\"\n          - \"# Directory to store version info\"\n          - \"$EC2ProgramDataDir = '{{EC2ProgramDataDir}}'\"\n          - \"# EC2 Binaries Zip Checksum\"\n          - \"$EC2BinariesZipCheckSum = '{{EC2BinariesZipCheckSum}}'\"\n          - \"# S3 Zip Url\"\n          - \"$S3ZipUrl = '{{S3ZipUrl}}'\"\n          - \"# AWS PS Enabled Feature Flag\"\n          - \"$AWSPSEnabled = '{{AWSPSEnabled}}'\"\n          - \"\"\n          - \"UpgradeEC2Binaries $S3BucketName $S3BucketKey $BinariesFilePath $EC2HostBinaryPath $EC2HostServiceName $EC2HostDisplayName $EC2HostServiceDescription $EC2HostServicePath $EC2HostSrcFileDir $EC2HostDestinationFileDir $EC2BinariesVersion $EC2VersionsFileName $EC2ProgramDataDir $EC2BinariesZipCheckSum $S3ZipUrl $AWSPSEnabled\"\n          - \"\""
  count           = var.is_ec2_mssql_enabled ? 1 : 0
  document_format = "YAML"
  document_type   = "Command"
  name            = "Clumio-UpgradeMssqlBinaries-${var.clumio_token}"
  tags = {
    "Vendor" : "Clumio"
  }
  target_type  = "/AWS::EC2::Instance"
  version_name = "Version-3"
}

resource "clumio_post_process_aws_connection" "clumio_callback" {
  account_id          = var.aws_account_id
  clumio_event_pub_id = aws_sns_topic.clumio_event_pub.arn
  config_version      = "4.4"
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
    aws_iam_role.clumio_s3_continuous_backup_event_bridge_role,
    aws_iam_policy.clumio_s3_continuous_backup_event_bridge_policy,
    aws_iam_policy.clumio_dynamodb_backup_policy,
    aws_iam_policy.clumio_dynamodb_restore_policy,
    aws_cloudwatch_event_target.clumio_dynamo_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_ebs_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ebs_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_ec2_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_ec2_cloudtrail_event_rule_target,
    aws_cloudwatch_event_target.clumio_rds_cloudwatch_event_rule_target,
    aws_cloudwatch_event_target.clumio_rds_cloudtrail_event_rule_target
  ]
  discover_version      = "4.6"
  intermediate_role_arn = "arn:aws:iam::${var.clumio_aws_account_id}:role/ClumioCustomerProtectRole"
  properties = {
    "ClumioS3ContinuousBackupEventBridgeRoleArn" : var.is_s3_enabled ? aws_iam_role.clumio_s3_continuous_backup_event_bridge_role[0].arn : "",
    "ClumioSSMNotificationRoleArn" : var.is_ec2_mssql_enabled ? aws_iam_role.clumio_ssm_notification_role[0].arn : "",
    "DynamoDbBackupPolicyArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_dynamodb_backup_policy[0].arn : "",
    "DynamoDbRestorePolicyArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_dynamodb_restore_policy[0].arn : "",
    "PermissionsBoundaryArn" : var.is_dynamodb_enabled ? aws_iam_policy.clumio_iam_permissions_boundary[0].arn : ""
  }
  protect_config_version             = "23.0"
  protect_dynamodb_version           = var.is_dynamodb_enabled ? "7.2" : ""
  protect_ebs_version                = var.is_ebs_enabled ? "24.1" : ""
  protect_ec2_mssql_version          = var.is_ec2_mssql_enabled ? "4.4" : ""
  protect_rds_version                = var.is_rds_enabled ? "20.3" : ""
  protect_s3_version                 = var.is_s3_enabled ? "6.1" : ""
  protect_warm_tier_dynamodb_version = var.is_dynamodb_enabled ? "5.0" : ""
  protect_warm_tier_version          = var.is_dynamodb_enabled ? "1.1" : ""
  region                             = var.aws_region
  role_arn                           = aws_iam_role.clumio_iam_role.arn
  role_external_id                   = var.role_external_id
  token                              = var.clumio_token
  wait_for_data_plane_resources      = var.wait_for_data_plane_resources
  wait_for_ingestion                 = var.wait_for_ingestion
}

resource "time_sleep" "wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule" {
  count           = var.is_s3_enabled ? 1 : 0
  create_duration = "10s"
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

resource "time_sleep" "wait_before_create" {
  create_duration = var.wait_time_before_create
}

