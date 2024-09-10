# clumio_ec2_backup_policy_document is the Clumio Managed IAM policy document for EBS/EC2 backups
# ResourceArns:
# Resource arns in policy statements have been defined as per EC2 resources types table at
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html#amazonec2-resources-for-iam-policies
# Tag Based Access Control Statements:
# Most of the policy statements in ClumioEc2BackupPolicy uses tag based conditions
# to provide access to the actions.
# Refer https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html for more details on the specifications.
# The following tags are used in the tag based conditions:
# 1.ClumioVendorTag - Vendor: Clumio
# This is a generic used to identify Clumio created resources in the customer account.
data "aws_iam_policy_document" "clumio_ec2_backup_policy_document" {
  # **** EBS Snapshot operations ****
  # EBS CreateSnapshot(s) actions are required to take point in time snapshots
  # of given volume/instance for backup.
  # Allow CreateSnapshot(s) only if the operation has ClumioVendorTag in the request.
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

  # Allow CreateSnapshot(s) on any instance or volume in AWS account.
  # However, snapshot created will be tagged with ClumioVendorTag.
  # as per statements AllowStartSnapshotWithClumioRequestTag.
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

  # Snapshots are deleted in 2 cases:
  # - Clumio maintains only one snapshot per volume per storage tier. During incremental backup,
  # older snapshots taken by previous backups are deleted.
  # - When a backup expires, snapshot associated with the backup(if any) is deleted.
  # Allow DeleteSnapshot operation on a snapshot only if it is tagged with ClumioVendorTag.
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


  # **** EC2 Image operations ****
  # RegisterImage operation is used in aws_snapshot backup operation to register image of given EC2 instance.
  # Allow RegisterImage on a snapshot only if it is tagged with ClumioVendorTag.
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

  # Allow RegisterImage operation on any image.
  # Register image operation do not support condition with request tags as per
  # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
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

  # Clumio AWS snapshot backup deregisters the image registered at the time of backup, if the backup fails
  # after the image has been registered.
  # Allow DeregisterImage only if the image has been tagged with ClumioVendorTag.
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

  # **** EC2 Tagging Operations ****
  # Deny direct CreateTags operation. Allow tag creation
  # only if it is associated with CreateSnapshot(s) operations.
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

  # Allow CreateTags operation only on an image only if one of the request tags is ClumioVendorTag.
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

  # Allow Delete Tags on an image or snapshot only if the resource is tagged with ClumioVendorTag.
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

  # **** EBS/EC2 Read Operations ****
  # Allow read operations on a given snapshot. Clumio backup uses these operations
  # to retrieve the data in a snapshot.
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

  # Allow describe operations on the resources which could be associated with an EC2 instance.
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

  # Allow read on a given instance profile.
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

  # Allow read on a given role.
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

# clumio_ec2_restore_policy_document is the Clumio Managed IAM policy document for EBS/EC2 restore.
# ResourceArns:
# Resource arns in policy statements have been defined as per EC2 resources types table at
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html#amazonec2-resources-for-iam-policies
# Tag Based Access Control Statements:
# Most of the policy statements used in ClumioEc2BackupPolicy and ClumioEc2RestorePolicy use tag based conditions
#  to provide access to the actions.
# Refer https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html for more details on the specifications.
# The following tags are used in the tag based conditions:
# 1.ClumioVendorTag - Vendor: Clumio
# This is a generic used to identify Clumio created resources in the customer account.
# 2. ClumioRestoreTag - clumio.restore.tag : "*"
# During the process of EC2/EBS Restore, this particular tag is intermittently applied to the resources
# until the completion of the restore.
data "aws_iam_policy_document" "clumio_ec2_restore_policy_document" {
  # **** EBS operations ****
  # Clumio restore task restores a snapshot in the following steps:
  # - starts a snapshot.
  # - puts the snapshot data of the volume to be restored in
  # the snapshot.
  # - complete the snashot.
  # Clumio restore task invokes StartSnapshot to restore a snapshot.
  # Allow StartSnapshot only if the request contains ClumioVendorTag.
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

  # Clumio restore task invokes CompleteSnapshot and CompleteSnapshot to restore a snapshot.
  # Allow snapshot operations only on snapshots with ClumioVendorTag.
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

  # Allow to create snapshot for any instance or volume in the AWS account.
  # However, the snapshot being created will be tagged with ClumioRestoreTag as per statements
  # CreateSnapshotWithRestoreTag.
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

  # Clumio restore uses CreateSnapshot(s) operations to generate AMI of a restored instance/volume.
  # Allow create snapshot with ClumioRestoreTag for volume restore.
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

  # **** EC2 volume operations ****
  # Clumio Restore invokes CreateVolume to create a restored volume.
  # Allow CreateVolume only if the operation request contains ClumioRestoreTag.
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

  # Clumio Restore deletes the restored volume in case restore fails after the volume has been created.
  # Allow DeleteVolume only if the volume is tagged with ClumioRestoreTag.
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

  # **** EC2 instance operations ****
  # Clumio Restore attaches the restored volumes to the restored instance or the instance specified in
  # EC2 restore volumes request.
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

  # Clumio restore detaches a restored volume from a restored instance if the restore fails
  # after attaching the volume to the instance.
  # DetachVolume from an instance only if the instance is a clumio restored instance.
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

  # Allow attach detach any volume as Clumio restore has the capability to attach/detach pre-existing volumes
  # in the account to the restored instance. However, the restore operation can detach volumes only
  # from Clumio restored instances as per the statement DetachVolumeFromClumioRestoredInstance.
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

  # **** EC2 image operations ****
  # Clumio restore uses RegisterImage operation to create an AMI, in case of a restore as an AMI image.
  # RegisterImage can be performed only on a clumio restored snapshot.
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

  # Register image operation does not support condition for request tags as per
  # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
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

  # Clumio restore de-registers the image if the restore operation has failed
  # after the register image operation.
  # DeregisterImage can be performed only on a clumio restored snapshot
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

  # Clumio restore uses run instance operation to launch a restored instance with the required resources.
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
      "arn:${data.aws_partition.current.partition}:ec2:*:*:subnet/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:key-pair/*",
      "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${var.aws_account_id}:security-group/*"
    ]
    sid = "RunInstance"
  }

  # Clumio restore performs instance based operations such as  StartInstances, StopInstances and
  # TerminateInstances at various steps in the instance restore task.
  # Allow the listed instance operations on on instances with ClumioRestoreTag.
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

  # **** EC2 Network Interface Operations ****
  # Clumio restore deletes the network interface created while launching the restored instance in case
  # restore failure after launching the instance.
  # DeleteNetworkInterface operation is allowed only if the interface is tagged with ClumioRestoreTag.
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

  # Clumio restore associates address to the network interfaces after restoring the instance.
  # Incase the restore fails after association of address to the network interfaces step,
  # then DisassociateAddress operation is performed.
  # AssociateAddress/DisassociateAddress operations are performed only on instances and network interfaces
  # tagged with ClumioRestoreTag.
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

  # **** EC2 Tagging operations ****
  # Clumio intends to create tags only on Clumio created resources so as to avoid extending
  # of Clumio Role"s access to other existing resources by allowing CreateTags operation.
  # Deny direct CreateTags operation. Allow tag creation on the listed resources
  # only if it is associated with CreateAction operations other than CreateTags.
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

  # Clumio creates image using register image operation which does not support
  # create tags as a dependent operation. Therefore, access to CreateTags is required by Clumio restore.
  # Allow CreateTags operation only on an image only if one of the request tags is ClumioRestoreTag.
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

  # DeleteTags is a delete operation which should be allowed only on resources
  # which has been created by Clumio operations to avoid accidental deletion of tags.
  # Allow Delete Tags on an image or snapshot only if the resource is tagged
  # with ClumioRestoreTag.
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

  # Access for PassRole is required to attach an instance profile to the restored instance.
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

  # **** EBS/EC2 Read Operations ****
  # Allow read operations on a given snapshot. Clumio restore uses these operations
  # to read the data in a snapshot.
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

  # Restore uses GetInstanceProfile operation to validate the instance profile
  # to be attached to the restored instance.
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

  # Restore uses GetRole operation to validate the given AWS role.
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

  # Restore uses the listed EC2 describe operations to validate the restored instances.
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

resource "aws_cloudwatch_event_rule" "clumio_ebs_cloudtrail_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EBS (CloudTrail)."
  event_pattern = "{\"source\": [\"aws.ec2\"],\"detail-type\": [\"AWS API Call via CloudTrail\"],\"detail\": {\"eventName\": [\"DeleteSnapshot\", \"LockSnapshot\", \"UnlockSnapshot\"],\"errorCode\": [{\"exists\": false}]}}"
  name          = "ClumioEBSCloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ebs_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EBS (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.ec2\"],\"detail-type\": [\"EBS Volume Notification\", \"EBS Snapshot Notification\"],\"detail\": {\"event\": [\"createVolume\",\"modifyVolume\",\"deleteVolume\",\"createSnapshot\",\"createSnapshots\",\"copySnapshot\",\"shareSnapshot\",\"lockDurationExpiry\",\"coolOffPeriodExpiry\"]}}"
  name          = "ClumioEBSCloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ebs_aws_backup_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for AWS recovery point resource changes in EBS (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.backup\"],\"detail-type\": [\"Recovery Point State Change\"],\"detail\": {\"resourceType\": [\"EBS\"], \"status\": [\"COMPLETED\", \"AVAILABLE\", \"PARTIAL\", \"EXPIRED\", \"DELETED\"]}}"
  name          = "ClumioEBSAWSBackupCWRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ec2_cloudtrail_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EC2 (CloudTrail)."
  event_pattern = "{ \"source\": [\"aws.ec2\"], \"detail-type\": [\"AWS API Call via CloudTrail\"], \"detail\": { \"eventName\": [ \"CreateImage\", \"DeregisterImage\", \"DeleteImage\", \"RegisterImage\", \"CopyImage\", \"AssociateIamInstanceProfile\", \"DisassociateIamInstanceProfile\", \"ReplaceIamInstanceProfileAssociation\", \"AttachVolume\", \"DetachVolume\"], \"errorCode\": [{\"exists\": false}] } }"
  name          = "ClumioEC2CloudtrailRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ec2_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EC2 (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.ec2\"], \"detail-type\": [\"EC2 Instance State-change Notification\"], \"detail\": {\"state\": [\"running\", \"stopped\", \"terminated\"]}}"
  name          = "ClumioEC2CloudwatchRule_${var.clumio_token}"
}

resource "aws_cloudwatch_event_rule" "clumio_ec2_aws_backup_cloudwatch_event_rule" {
  count         = var.is_ebs_enabled ? 1 : 0
  depends_on    = [time_sleep.wait_before_create]
  description   = "Watches for resource changes in EC2 (CloudWatch)."
  event_pattern = "{\"source\": [\"aws.backup\"],\"detail-type\": [\"Recovery Point State Change\"],\"detail\": {\"resourceType\": [\"EC2\"], \"status\": [\"COMPLETED\", \"AVAILABLE\", \"PARTIAL\", \"EXPIRED\", \"DELETED\"]}}"
  name          = "ClumioEC2AWSBackupCWRule_${var.clumio_token}"
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

resource "aws_cloudwatch_event_target" "clumio_ebs_aws_backup_cloudwatch_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ebs_aws_backup_cloudwatch_event_rule[0].name
  target_id = "clumio-ebs-aws-backup-cwatch-publish"
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

resource "aws_cloudwatch_event_target" "clumio_ec2_aws_backup_cloudwatch_event_rule_target" {
  count     = var.is_ebs_enabled ? 1 : 0
  arn       = aws_sns_topic.clumio_event_pub.arn
  rule      = aws_cloudwatch_event_rule.clumio_ec2_aws_backup_cloudwatch_event_rule[0].name
  target_id = "clumio-ec2-aws-backup-cwatch-publish"
}

# clumio_ec2_backup_policy is the Clumio Managed IAM policy for EBS/EC2 backups
resource "aws_iam_policy" "clumio_ec2_backup_policy" {
  count = var.is_ebs_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioEC2BackupPolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_ec2_backup_policy_document.json
}

# clumio_ec2_restore_policy is the Clumio Managed IAM policy for EBS/EC2 restore.
resource "aws_iam_policy" "clumio_ec2_restore_policy" {
  count = var.is_ebs_enabled ? 1 : 0
  depends_on = [
    time_sleep.wait_before_create
  ]
  name   = "ClumioEC2RestorePolicy-${var.aws_region}-${var.clumio_token}"
  path   = var.path
  policy = data.aws_iam_policy_document.clumio_ec2_restore_policy_document.json
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

