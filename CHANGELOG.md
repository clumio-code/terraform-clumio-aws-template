## 0.14.0
Role chaining enabled by default and s3 permissions change.

## 0.13.0
Updates to s3 policy document permissions.

## 0.12.2
Added permissions boundary to the clumio_s3_continuous_backup_event_bridge_role resource.

## 0.12.1
Updated required provider version for clumio to ~>0.5.0 and documentation updates.

## 0.12.0
- Updates to s3 policy document permissions.
- Changes related to role chaining. A new variable access_via_role_chaining is added which if
set to true will enable role chaining. This will be by default set to true in future once role chaining
becomes the default behavior. 

## 0.11.1
Updated required provider version for clumio to work with 0.4.x and 0.5.x versions of provider.

## 0.11.0
Permission changes to DynamoDB protect policy.

## 0.10.0
Updates to EC2 Mssql policy permissions.

## 0.9.0
Updates to s3 discover policy permissions and role name change to include region in the name for EC2 Mssql.

## 0.8.1
Bug fix.

## 0.8.0
- Updates to RDS policy permissions.
- Attached clumio_kms_managed_policy to clumio_iam_role.

## 0.7.0
Updates to DynamoDB protect policy permissions.

## 0.6.0
Updates to S3 protect policy permissions.

## 0.5.0
- Added permissions boundary for clumio roles.
- Added conditional statements to discover policy so that permissions are added only if the corresponding data source is enabled.

## 0.4.0
- Updates to DynamoDB policy permissions.
- Updated Clumio Provider version required to ~>0.4.0

## 0.3.0
Added is_dynamodb_enabled check for clumio_iam_role_policy and permissions_boundary resources.

## 0.2.0
Updates to EBS, RDS and S3 policy permissions.

## 0.1.0
clumio provider required version changed to ~>0.3.0

## 0.0.5
Changes to make RDS related resources independent of EBS.

## 0.0.4
- Consolidated configuration related changes.
- Required version of TF provider changed to 0.2.3.

## 0.0.3
Added the dynamodb check in the properties for post_process_aws_connection.

## 0.0.2
Changes to include DynamoDB related resources.

## 0.0.1
Initial release.
