terraform {
  required_providers {
    aws = {}
    clumio = {
      source  = "clumio-code/clumio"
      version = ">=0.12.0, <0.14.0"
    }
  }
}
