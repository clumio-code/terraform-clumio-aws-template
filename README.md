<!-- BEGIN_TF_DOCS -->

# Clumio AWS Terraform Module

Terraform module to install the Clumio required AWS resources in the customer AWS account.

## Usage:
This module is to be used along with the resource clumio_aws_connection as some of the inputs for the module are obtained from the output of clumio_aws_connection resource.
Below is an example of using the module:

```hcl
data aws_caller_identity current {
}

data aws_region current {
}


resource "clumio_aws_connection" "test_conn" {
  account_native_id = data.aws_caller_identity.current.account_id
  aws_region = data.aws_region.current.name
  description = data.aws_caller_identity.current.account_id
  protect_asset_types_enabled = ["EBS", "RDS", "DynamoDB", "EC2MSSQL", "S3"]
  services_enabled = ["discover", "protect"]
}

################################################################################
# Clumio AWS Connection Module
################################################################################

module clumio_aws_connection_module {
    providers = {
    aws = aws
    clumio = clumio
    }
    source = "../../"
    clumio_token = clumio_aws_connection.test_conn.token
    role_external_id = "RoleExternalId_${clumio_aws_connection.test_conn.token}"
    aws_region = clumio_aws_connection.test_conn.aws_region
    aws_account_id = data.aws_caller_identity.current.account_id
    clumio_aws_account_id = clumio_aws_connection.test_conn.clumio_aws_account_id
    is_ebs_enabled = true
    is_rds_enabled = true
    is_ec2_mssql_enabled = true
    is_s3_enabled = true
    is_dynamodb_enabled = true
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >=0.14.0 |
| <a name="requirement_clumio"></a> [clumio](#requirement\_clumio) | ~>0.2.2 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_clumio"></a> [clumio](#provider\_clumio) | ~>0.2.2 |
| <a name="provider_time"></a> [time](#provider\_time) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.clumio_dynamo_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ebs_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ebs_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ec2_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_ec2_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_rds_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_rds_cloudwatch_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_s3_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.clumio_tag_event_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
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
| [aws_iam_policy.clumio_discover_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_dynamodb_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_ec2_mssql_protect_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_ec2_protect_managed_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_iam_permissions_boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_iam_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_s3_protect_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.clumio_warm_protect_dynamodb_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.clumio_ec2_mssql_ssm_instance_role_v2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_iam_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_ssm_notification_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.clumio_support_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.clumio_base_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_drift_detect_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_ec2_mssql_ssm_instance_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_rds_protect_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_ssm_notification_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.clumio_support_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.clumio_ec2_mssql_protect_policy_role_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_discover_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_dynamodb_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_ec2_protect_managed_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_s3_protect_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_clumio_warm_protect_dynamodb_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.clumio_iam_role_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_sns_topic.clumio_event_pub](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.clumio_event_pub_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [clumio_post_process_aws_connection.clumio_callback](https://registry.terraform.io/providers/clumio-code/clumio/latest/docs/resources/clumio_post_process_aws_connection) | resource |
| [time_sleep.wait_10_seconds_before_creating_clumio_s3_cloudtrail_event_rule](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_30_seconds_for_iam_propagation](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_5_seconds_for_clumio_s3_protect_policy](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [time_sleep.wait_before_create](https://registry.terraform.io/providers/hashicorp/time/latest/docs/resources/sleep) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_canonical_user_id.canonical_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/canonical_user_id) | data source |
| [aws_iam_policy_document.aws_iam_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_base_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_discover_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_drift_detect_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_dynamodb_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_protect_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_mssql_ssm_instance_role_v2_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ec2_protect_managed_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_event_pub_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_iam_permissions_boundary_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_iam_role_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_rds_protect_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_s3_protect_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ssm_notification_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_ssm_notification_role_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_support_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.clumio_warm_protect_dynamodb_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_account_id"></a> [aws\_account\_id](#input\_aws\_account\_id) | Client AWS Account Id | `string` | n/a | yes |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS Region | `string` | n/a | yes |
| <a name="input_clumio_aws_account_id"></a> [clumio\_aws\_account\_id](#input\_clumio\_aws\_account\_id) | Clumio Control Plane Account Id | `string` | n/a | yes |
| <a name="input_clumio_token"></a> [clumio\_token](#input\_clumio\_token) | The AWS integration ID token. | `string` | n/a | yes |
| <a name="input_is_dynamodb_enabled"></a> [is\_dynamodb\_enabled](#input\_is\_dynamodb\_enabled) | Flag to indicate if Clumio Protect for dynamodb is enabled | `bool` | `false` | no |
| <a name="input_is_ebs_enabled"></a> [is\_ebs\_enabled](#input\_is\_ebs\_enabled) | Flag to indicate if Clumio Protect for ebs is enabled | `bool` | `false` | no |
| <a name="input_is_ec2_mssql_enabled"></a> [is\_ec2\_mssql\_enabled](#input\_is\_ec2\_mssql\_enabled) | Flag to indicate if Clumio Protect for ec2\_mssql is enabled | `bool` | `false` | no |
| <a name="input_is_protect_enabled"></a> [is\_protect\_enabled](#input\_is\_protect\_enabled) | Flag to indicate if Clumio Protect for ebs is enabled | `bool` | `true` | no |
| <a name="input_is_rds_enabled"></a> [is\_rds\_enabled](#input\_is\_rds\_enabled) | Flag to indicate if Clumio Protect for rds is enabled | `bool` | `false` | no |
| <a name="input_is_s3_enabled"></a> [is\_s3\_enabled](#input\_is\_s3\_enabled) | Flag to indicate if Clumio Protect for S3 is enabled | `bool` | `false` | no |
| <a name="input_path"></a> [path](#input\_path) | Value of path set on the AWS IAM roles, policies and instance\_profile resources of the module. If not specified the default value is /clumio/. | `string` | `"/clumio/"` | no |
| <a name="input_role_external_id"></a> [role\_external\_id](#input\_role\_external\_id) | A key that must be used by Clumio to assume the service role in your account. This should be a secure string, like a password, but it does not need to be remembered (random characters are best). | `string` | n/a | yes |
| <a name="input_wait_time_before_create"></a> [wait\_time\_before\_create](#input\_wait\_time\_before\_create) | Time in seconds to wait before creation of resources. This will be required to be set to a value above 45s in the case of shifting from old terraform template to the module based template. | `string` | `"60s"` | no |

## Deprecated Inputs
The following inputs are deprecated and will be removed in the next version of the module.
Instead of these two deprecated inputs, use [is_dynamodb_enabled](#input\_is\_dynamodb\_enabled).

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_is_warmtier_dynamodb_enabled"></a> [is\_warmtier\_dynamodb\_enabled](#input\_is\_warmtier\_dynamodb\_enabled) | Flag to indicate if Clumio Protect for warmtier dynamodb is enabled | `bool` | `false` | no |
| <a name="input_is_warmtier_enabled"></a> [is\_warmtier\_enabled](#input\_is\_warmtier\_enabled) | Flag to indicate if Clumio Protect for warmtier is enabled | `bool` | `false` | no |


## Outputs

No outputs.


<!-- END_TF_DOCS -->
