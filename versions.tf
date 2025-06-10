terraform {
  required_providers {
    aws = {}
    clumio = {
      source  = "clumio-code/clumio"
      version = ">=0.13.0, <0.15.0"
    }
  }
}
