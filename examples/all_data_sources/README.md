<!-- BEGIN_TF_DOCS -->
# Clumio AWS Connection

Configuration in this directory creates a Creates a Clumio AWS Connection and then invokes the clumio_aws_connection_module to install all the AWS resources required by Clumio in the customer account.

In the module, the flags for all the data sources are set to true.

## Usage
To run this example you need to execute:

```
$ terraform init
$ terraform plan
$ terraform apply
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_clumio"></a> [clumio](#requirement\_clumio) | ~>0.2.2 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_clumio"></a> [clumio](#provider\_clumio) | ~>0.2.2 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_clumio_aws_connection_module"></a> [clumio\_aws\_connection\_module](#module\_clumio\_aws\_connection\_module) | ../../ | n/a |

## Resources

| Name | Type |
|------|------|
| [clumio_aws_connection.test_conn](https://registry.terraform.io/providers/clumio-code/clumio/latest/docs/resources/clumio_aws_connection) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_clumio_api_base_url"></a> [clumio\_api\_base\_url](#input\_clumio\_api\_base\_url) | Base URL for Clumio APIs. | `string` | n/a | yes |
| <a name="input_clumio_api_token"></a> [clumio\_api\_token](#input\_clumio\_api\_token) | API Token required to invoke Clumio APIs. | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
