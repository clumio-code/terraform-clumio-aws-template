<!-- BEGIN_TF_DOCS -->

# Clumio AWS Terraform Module

Terraform module to install the Clumio required AWS resources in the customer AWS account.

## Usage
This module is to be used along with the resource clumio_aws_connection as some of the inputs for the module are obtained from the output of clumio_aws_connection resource.
Below is an example of using the module:

```hcl
data "aws_caller_identity" "current" {
}

data "aws_region" "current" {
}


resource "clumio_aws_connection" "test_conn" {
  account_native_id = data.aws_caller_identity.current.account_id
  aws_region        = data.aws_region.current.name
  description       = data.aws_caller_identity.current.account_id
}

################################################################################
# Clumio AWS Connection Module
################################################################################

module "clumio_aws_connection_module" {
  providers = {
    aws    = aws
    clumio = clumio
  }
  source                = "../../"
  clumio_token          = clumio_aws_connection.test_conn.token
  role_external_id      = clumio_aws_connection.test_conn.role_external_id
  aws_region            = clumio_aws_connection.test_conn.aws_region
  aws_account_id        = data.aws_caller_identity.current.account_id
  clumio_aws_account_id = clumio_aws_connection.test_conn.clumio_aws_account_id
  is_ebs_enabled        = true
  is_rds_enabled        = true
  is_ec2_mssql_enabled  = true
  is_s3_enabled         = true
  is_dynamodb_enabled   = true
}
```
## Upgrading module
Run the following terraform commands to upgrade from a older version of the module.
```terraform
terraform init -upgrade
terraform plan
terraform apply
```
Note: If the module block has explicit version specified, then the version must be changed before running the above commands.

For example, in the below config the module has version 0.26.0 as shown below:
```hcl
module "clumio_aws_connection_module" {
  providers = {
  aws    = aws
  clumio = clumio
  }
  source                = "../../"
  version               = "0.26.0"
  clumio_token          = clumio_aws_connection.test_conn.token
  role_external_id      = clumio_aws_connection.test_conn.role_external_id
  aws_region            = clumio_aws_connection.test_conn.aws_region
  aws_account_id        = data.aws_caller_identity.current.account_id
  clumio_aws_account_id = clumio_aws_connection.test_conn.clumio_aws_account_id
  is_ebs_enabled        = true
  is_rds_enabled        = true
  is_ec2_mssql_enabled  = true
  is_s3_enabled         = true
  is_dynamodb_enabled   = true
}
```
To upgrade the module version to 0.27.0, the version number should be updated in the config as shown below.
```hcl
module "clumio_aws_connection_module" {
  providers = {
  aws    = aws
  clumio = clumio
  }
  source                = "../../"
  version               = "0.27.0"
  clumio_token          = clumio_aws_connection.test_conn.token
  role_external_id      = clumio_aws_connection.test_conn.role_external_id
  aws_region            = clumio_aws_connection.test_conn.aws_region
  aws_account_id        = data.aws_caller_identity.current.account_id
  clumio_aws_account_id = clumio_aws_connection.test_conn.clumio_aws_account_id
  is_ebs_enabled        = true
  is_rds_enabled        = true
  is_ec2_mssql_enabled  = true
  is_s3_enabled         = true
  is_dynamodb_enabled   = true
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_clumio"></a> [clumio](#requirement\_clumio) | >=0.9.0, <0.11.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.63.1 |
| <a name="provider_clumio"></a> [clumio](#provider\_clumio) | 0.10.1 |
| <a name="provider_time"></a> [time](#provider\_time) | 0.12.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.clumio_aws_backup_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ebs_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ebs_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ec2_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ec2_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_rds_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_rds_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_s3_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_tag_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.clumio_aws_backup_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_dynamo_cloudtrail_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_ebs_cloudtrail_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_ebs_cloudwatch_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_ec2_cloudtrail_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_ec2_cloudwatch_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_rds_cloudtrail_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_rds_cloudwatch_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_s3_cloudtrail_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.clumio_tag_event_rule_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_iam_instance_profile.clumio_ec2_mssql_ssm_instance_profile](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_policy.clumio_base_managed_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_dynamodb_backup_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_dynamodb_restore_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_ec2_backup_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_ec2_mssql_backup_restore_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_ec2_restore_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_iam_permissions_boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_rds_backup_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_rds_restore_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_s3_backup_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_s3_continuous_backup_event_bridge_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_s3_restore_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.clumio_ec2_mssql_ssm_instance_role_v2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_iam_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_s3_continuous_backup_event_bridge_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_ssm_notification_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_support_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.clumio_drift_detect_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_ec2_mssql_ssm_instance_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_iam_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_inventory_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_kms_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_ssm_notification_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_support_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.clumio_ec2_mssql_backup_restore_policy_role_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_base_managed_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_dynamodb_backup_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_dynamodb_restore_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_ec2_backup_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_ec2_restore_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_rds_backup_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_rds_restore_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_s3_backup_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_s3_restore_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_s3_continuous_backup_event_bridge_role_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_key.clumio_event_pub_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_sns_topic.clumio_event_pub](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.clumio_event_pub_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_ssm_document.ssm_document_ag_database_details](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_ag_details](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_change_install_path](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_copy_host_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_executable_invocation_script](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_get_active_fci_instance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_get_all_services](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_install_mssql_binaries](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_inventory_sync](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_invoke_ps_script](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_mssql_prereq_heartbeat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_normal_heartbeat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_remove_old_inventory_files](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_ssm_check_heartbeat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_system_heartbeat](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [aws_ssm_document.ssm_document_upgrade_mssql_binaries](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_document) | resource |
| [clumio_post_process_aws_connection.clumio_callback](https://registry.terraform.io/providers/clumio-code/clumio/latest/docs/resources/post_process_aws_connection) | resource |
| [time_sleep.wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_30_seconds_for_iam_propagation](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_5_seconds_for_clumio_base_managed_policy](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_5_seconds_for_clumio_s3_backup_policy](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_5_seconds_for_clumio_s3_restore_policy](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_before_create](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.aws_iam_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.aws_support_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_base_managed_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_drift_detect_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_dynamodb_backup_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_dynamodb_restore_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_backup_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_backup_restore_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_role_v2_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_restore_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_event_pub_key_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_event_pub_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_iam_permissions_boundary_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_iam_role_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_inventory_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_kms_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_rds_backup_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_rds_restore_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_s3_backup_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_s3_continuous_backup_event_bridge_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_s3_continuous_backup_event_bridge_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_s3_restore_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ssm_notification_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ssm_notification_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_support_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_account_id"></a> [aws\_account\_id](#input\_aws\_account\_id) | Client AWS Account Id. | `string` | n/a | yes |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS Region. | `string` | n/a | yes |
| <a name="input_clumio_aws_account_id"></a> [clumio\_aws\_account\_id](#input\_clumio\_aws\_account\_id) | Clumio Control Plane Account Id. | `string` | n/a | yes |
| <a name="input_clumio_iam_role_tags"></a> [clumio\_iam\_role\_tags](#input\_clumio\_iam\_role\_tags) | Additional tags for Clumio IAM Roles. | `map(string)` | <pre>{<br>  "Vendor": "Clumio"<br>}</pre> | no |
| <a name="input_clumio_inventory_sns_topic_encryption_key"></a> [clumio\_inventory\_sns\_topic\_encryption\_key](#input\_clumio\_inventory\_sns\_topic\_encryption\_key) | Optional existing KMS Key for the Clumio Inventory SNS topic. If one is provided, it MUST have a key policy similar to the one denoted in data.aws\_iam\_policy\_document.clumio\_event\_pub\_key\_policy\_document in [common.tf](https://github.com/clumio-code/terraform-clumio-aws-template/blob/main/common.tf). | `string` | `null` | no |
| <a name="input_clumio_token"></a> [clumio\_token](#input\_clumio\_token) | The AWS integration ID token. | `string` | n/a | yes |
| <a name="input_create_clumio_inventory_sns_topic_encryption_key"></a> [create\_clumio\_inventory\_sns\_topic\_encryption\_key](#input\_create\_clumio\_inventory\_sns\_topic\_encryption\_key) | Indicates that a KMS Key must be created and associated with the Clumio Inventory SNS topic. | `bool` | `false` | no |
| <a name="input_data_plane_account_id"></a> [data\_plane\_account\_id](#input\_data\_plane\_account\_id) | Allow only one role in clumio control plane to assume the ClumioIAMRole in customer's account. | `string` | `"*"` | no |
| <a name="input_is_dynamodb_enabled"></a> [is\_dynamodb\_enabled](#input\_is\_dynamodb\_enabled) | Flag to indicate if Clumio Protect and Discover for DynamoDB are enabled | `bool` | `false` | no |
| <a name="input_is_ebs_enabled"></a> [is\_ebs\_enabled](#input\_is\_ebs\_enabled) | Flag to indicate if Clumio Protect and Discover for EBS are enabled | `bool` | `false` | no |
| <a name="input_is_ec2_mssql_enabled"></a> [is\_ec2\_mssql\_enabled](#input\_is\_ec2\_mssql\_enabled) | Flag to indicate if Clumio Protect and Discover for Mssql on EC2 are enabled | `bool` | `false` | no |
| <a name="input_is_rds_enabled"></a> [is\_rds\_enabled](#input\_is\_rds\_enabled) | Flag to indicate if Clumio Protect and Discover for RDS are enabled | `bool` | `false` | no |
| <a name="input_is_s3_enabled"></a> [is\_s3\_enabled](#input\_is\_s3\_enabled) | Flag to indicate if Clumio Protect and Discover for S3 are enabled | `bool` | `false` | no |
| <a name="input_path"></a> [path](#input\_path) | Value of path set on the AWS IAM roles, policies and instance\_profile resources of the module. If not specified the default value is /clumio/. | `string` | `"/clumio/"` | no |
| <a name="input_permissions_boundary_arn"></a> [permissions\_boundary\_arn](#input\_permissions\_boundary\_arn) | ARN of the permissions boundary to be set on Clumio Roles. | `string` | `""` | no |
| <a name="input_role_external_id"></a> [role\_external\_id](#input\_role\_external\_id) | A key that must be used by Clumio to assume the service role in your account. This should be a secure string, like a password, but it does not need to be remembered (random characters are best). | `string` | n/a | yes |
| <a name="input_wait_for_data_plane_resources"></a> [wait\_for\_data\_plane\_resources](#input\_wait\_for\_data\_plane\_resources) | Flag to indicate if we need to wait for data plane resources to be created. | `bool` | `false` | no |
| <a name="input_wait_for_ingestion"></a> [wait\_for\_ingestion](#input\_wait\_for\_ingestion) | Flag to indicate if we need to wait for ingestion to complete. | `bool` | `false` | no |
| <a name="input_wait_time_before_create"></a> [wait\_time\_before\_create](#input\_wait\_time\_before\_create) | Time in seconds to wait before creation of resources. This will be required to be set to a value above 45s in the case of shifting from old terraform template to the module based template. | `string` | `"60s"` | no |

## Outputs

No outputs.

<!-- END_TF_DOCS -->
