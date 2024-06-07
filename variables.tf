variable "aws_account_id" {
  description = "Client AWS Account Id."
  type = string
}

variable "aws_region" {
  description = "AWS Region."
  type = string
}

variable "clumio_aws_account_id" {
  description = "Clumio Control Plane Account Id."
  type = string
}

variable "clumio_iam_role_tags" {
  description = "Additional tags for Clumio IAM Roles."
  type = map(string)
  default = {
    Vendor = "Clumio"
  }
}

variable "clumio_token" {
  description = "The AWS integration ID token."
  type = string
}

variable "data_plane_account_id" {
  description = "Allow only one role in clumio control plane to assume the ClumioIAMRole in customer's account."
  type = string
  default = "*"
}

variable "is_dynamodb_enabled" {
  description = "Flag to indicate if Clumio Protect and Discover for DynamoDB are enabled"
  type = bool
  default = false
}

variable "is_ebs_enabled" {
  description = "Flag to indicate if Clumio Protect and Discover for EBS are enabled"
  type = bool
  default = false
}

variable "is_ec2_mssql_enabled" {
  description = "Flag to indicate if Clumio Protect and Discover for Mssql on EC2 are enabled"
  type = bool
  default = false
}

variable "is_rds_enabled" {
  description = "Flag to indicate if Clumio Protect and Discover for RDS are enabled"
  type = bool
  default = false
}

variable "is_s3_enabled" {
  description = "Flag to indicate if Clumio Protect and Discover for S3 are enabled"
  type = bool
  default = false
}

variable "path" {
  description = "Value of path set on the AWS IAM roles, policies and instance_profile resources of the module. If not specified the default value is /clumio/."
  type = string
  default = "/clumio/"
}

variable "permissions_boundary_arn" {
  description = "ARN of the permissions boundary to be set on Clumio Roles."
  type = string
  default = ""
}

variable "role_external_id" {
  description = "A key that must be used by Clumio to assume the service role in your account. This should be a secure string, like a password, but it does not need to be remembered (random characters are best)."
  type = string
}

variable "wait_for_data_plane_resources" {
  description = "Flag to indicate if we need to wait for data plane resources to be created."
  type = bool
  default = false
}

variable "wait_for_ingestion" {
  description = "Flag to indicate if we need to wait for ingestion to complete."
  type = bool
  default = false
}

variable "wait_time_before_create" {
  description = "Time in seconds to wait before creation of resources. This will be required to be set to a value above 45s in the case of shifting from old terraform template to the module based template."
  type = string
  default = "60s"
}

variable create_clumio_inventory_sns_topic_encryption_key {
  description = "Indicates that a KMS Key must be created and associated with the Clumio Inventory SNS topic."
  type = bool
  default = false
}

variable "clumio_inventory_sns_topic_encryption_key" {
  description = "Encryption Key for the Clumio Inventory SNS topic."
  type = string
  default = null
}
