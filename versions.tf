terraform {
  required_providers {
    aws = {}
    clumio = {
      source  = "clumio-code/clumio"
      version = ">=0.20.0, <0.22.0"
    }
  }
}
