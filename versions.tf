terraform {
  required_providers {
    aws = {}
    clumio = {
      source  = "clumio-code/clumio"
      version = ">=0.22.0, <0.24.0"
    }
  }
}
