data "aws_iam_policy_document" "clumio_rds_backup_policy_document" {
  # Required to copy and sharing the cluster snapshot to and from Clumio.
  statement {
    actions = [
      "rds:CopyDBClusterSnapshot",
      "rds:ModifyDBClusterSnapshotAttribute"
    ]
    effect = "Allow"
    resources = [
      # Allow actions on customer account.
      "arn:${local.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      # Allow actions on Clumio account.
      "arn:${local.partition}:rds:*:${var.data_plane_account_id}:cluster-snapshot:*"
    ]
    sid = "CopyAndSharingClusterSnapshotToClumio"
  }

  # Required to copy and sharing the instance snapshot to and from Clumio.
  statement {
    actions = [
      "rds:CopyDBSnapshot",
      "rds:ModifyDBSnapshotAttribute"
    ]
    effect = "Allow"
    resources = [
      # Allow actions on customer account.
      "arn:${local.partition}:rds:*:${var.aws_account_id}:snapshot:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:og:*",
      # Allow actions on Clumio account.
      "arn:${local.partition}:rds:*:${var.data_plane_account_id}:snapshot:*",
      "arn:${local.partition}:rds:*:${var.data_plane_account_id}:og:*"
    ]
    sid = "CopyAndSharingInstanceSnapshotToClumio"
  }

  # Required for taking cluster snapshot for Clumio backup.
  statement {
    actions = [
      "rds:CreateDBClusterSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*"
    ]
    sid = "CreateClusterSnapshotForClumioBackup"
  }

  # Required to read cluster snapshots for backup.
  statement {
    actions = [
      "rds:DescribeDBClusterSnapshots"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "DescribeClusterSnapshots"
  }

  # Required for taking instance snapshot for Clumio backup.
  statement {
    actions = [
      "rds:CreateDBSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:snapshot:*"
    ]
    sid = "CreateInstanceSnapshotForClumioBackup"
  }

  # Required for backing up the RDS subnet configuration.
  statement {
    actions = [
      "rds:DescribeDBSubnetGroups"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "BackingUpSubnetGroups"
  }

  # Required to add a Clumio tag in the Clumio-taken snapshot.
  statement {
    actions = [
      "rds:AddTagsToResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:snapshot:*"
    ]
    sid = "AddingClumioTagToSnapshot"
  }

  # Required for backing up the RDS option groups.
  statement {
    actions = [
      "rds:ModifyOptionGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "BackingUpOptionGroups"
  }

  # Required for apply PITR configuration on the RDS cluster.
  statement {
    actions = [
      "rds:ModifyDBCluster"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*"
    ]
    sid = "ApplyPITRConfigurationOnCluster"
  }

  # Required for apply PITR configuration on the RDS instance.
  statement {
    actions = [
      "rds:ModifyDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:secgrp:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*"
    ]
    sid = "ApplyPITRConfigurationOnInstance"
  }

  # Required to read the RDS security group.
  statement {
    actions = [
      "ec2:DescribeSecurityGroups"
    ]
    effect = "Allow"
    # ec2:DescribeSecurityGroups only support the all resources wildcard('*').
    resources = [
      "*"
    ]
    sid = "ReadRDSSecurityGroupsPermissions"
  }

  # Required to identify the Clumio backed up instance/cluster for cleanup.
  statement {
    actions = [
      "rds:ListTagsForResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:snapshot:*"
    ]
    sid = "ListClumioTagsForSnapshots"
  }

  # Required to clean up Clumio-created temporary cluster snapshot.
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

  # Required to clean up Clumio-created temporary instance snapshot.
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

  # Required during the backup and restore of an RDS instance/cluster.
  statement {
    actions = [
      "kms:CreateGrant"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:kms:*:*:key/*"
    ]
    sid = "BackupKMSPermissions"
  }
}

data "aws_iam_policy_document" "clumio_rds_restore_policy_document" {
  # Required to identify the Clumio restored instance/cluster for cleanup.
  statement {
    actions = [
      "rds:ListTagsForResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "ListClumioTagsForRestoredTag"
  }

  # Required to restore a RDS instance in the RDS cluster.
  statement {
    actions = [
      "rds:CreateDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:secgrp:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreInstancesInACluster"
  }

  # Required to restore the parameter group configuration.
  statement {
    actions = [
      "rds:CreateDBParameterGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:pg:*"
    ]
    sid = "RestoreParameterGroups"
  }

  # Required to restore a RDS instance from the snapshot.
  statement {
    actions = [
      "rds:RestoreDBInstanceFromDBSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:snapshot:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreInstanceFromSnapshot"
  }

  # Required to restore a RDS instance from its point in time configuration.
  statement {
    actions = [
      "rds:RestoreDBInstanceToPointInTime"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:auto-backup:*"
    ]
    sid = "RestoreInstanceToPointInTime"
  }

  # Required to restore the RDS cluster from the snapshot.
  statement {
    actions = [
      "rds:RestoreDBClusterFromSnapshot"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreClusterFromSnapshot"
  }

  # Required to restore a RDS cluster from its point in time configuration.
  statement {
    actions = [
      "rds:RestoreDBClusterToPointInTime"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-pg:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:subgrp:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:auto-backup:*"
    ]
    sid = "RestoreClusterToPointInTime"
  }

  # Required to remove the Clumio tag from the restored RDS instance/cluster.
  statement {
    actions = [
      "rds:RemoveTagsFromResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster-snapshot:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db-snapshot:*"
    ]
    sid = "RemoveClumioTagAfterRestore"
  }

  # Required to identify the Clumio restored instance/cluster for cleanup.
  statement {
    actions = [
      "rds:AddTagsToResource"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "AddingClumioTagToRestoredRDSResource"
  }

  # Required to restore the option group in Clumio restored instance/cluster.
  # Wildcard required in resource arn for cross-region restores.
  statement {
    actions = [
      "rds:CreateOptionGroup"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:og:*"
    ]
    sid = "RestoreOptionGroups"
  }

  # Required to restore the read-replicas for Clumio restored instance/cluster.
  # Wildcard is used for regions so that we can create read-replicas in the regions
  # that are not connected to Clumio.
  statement {
    actions = [
      "rds:CreateDBInstanceReadReplica"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:*:${var.aws_account_id}:cluster:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:db:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:og:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:pg:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:cluster-pg:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:secgrp:*",
      "arn:${local.partition}:rds:*:${var.aws_account_id}:subgrp:*"
    ]
    sid = "RestoreReadReplicas"
  }

  # Required to clean the Clumio-created RDS cluster on failure.
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
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "ClusterCleanupPermissions"
  }

  # Required to clean the Clumio-created RDS instance on failure.
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
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "InstanceCleanupPermissions"
  }

  # Required to associate IAM role(s) for Clumio restored cluster.
  statement {
    actions = [
      "rds:AddRoleToDBCluster"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:cluster:*"
    ]
    sid = "RestoreAssociatedRolesInCluster"
  }

  # Required to associate IAM role(s) for Clumio restored instance.
  statement {
    actions = [
      "rds:AddRoleToDBInstance"
    ]
    effect = "Allow"
    resources = [
      "arn:${local.partition}:rds:${var.aws_region}:${var.aws_account_id}:db:*"
    ]
    sid = "RestoreAssociatedRolesInInstance"
  }

  # Required to pass the associated IAM role(s) to Clumio restored instance/cluster.
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
      "arn:${local.partition}:iam::${var.aws_account_id}:role/*"
    ]
    sid = "PassAssociatedRoles"
  }
}

resource "aws_cloudwatch_event_rule" "clumio_rds_cloudtrail_event_rule" {
  count         = var.is_rds_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in RDS (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.rds\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"DeleteDBSnapshot\",\"DeleteDBClusterSnapshot\",\"CopyDBClusterSnapshot\",\"CopyDBSnapshot\",\"CreateDBCluster\",\"DeleteDBCluster\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioRDSCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_rds_cloudwatch_event_rule" {
  count         = var.is_rds_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in RDS (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.rds\"], \"detail-type\": [\"RDS DB Instance Event\",\"RDS DB Snapshot Event\",\"RDS DB Cluster Event\",\"RDS DB Cluster Snapshot Event\"], \"detail\": {\"SourceType\": [\"DB_INSTANCE\", \"SNAPSHOT\", \"CLUSTER\", \"CLUSTER_SNAPSHOT\"]}}"
  name          = "ClumioRDSCloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_rds_aws_backup_cloudwatch_event_rule" {
  count         = var.is_rds_enabled && var.collect_inventory_aws_backup_recovery_points ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for AWS RDS recovery point resource changes (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.backup\"],\"detail-type\": [\"Recovery Point State Change\"],\"detail\": {\"resourceType\": [\"Aurora\", \"RDS\", \"RDS.Cluster\"], \"status\": [\"COMPLETED\", \"AVAILABLE\", \"PARTIAL\", \"EXPIRED\", \"DELETED\"]}}"
  name          = "ClumioRDSAWSBackupCWRule_${var.clumio_token}"
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

resource "aws_cloudwatch_event_target" "clumio_rds_aws_backup_cloudwatch_event_rule_target" {
  count     = var.is_rds_enabled && var.collect_inventory_aws_backup_recovery_points ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_rds_aws_backup_cloudwatch_event_rule[0].name
  target_id = "clumio-rds-aws-backup-cwatch-publish"
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

