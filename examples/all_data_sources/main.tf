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
