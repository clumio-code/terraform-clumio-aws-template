terraform {
  required_providers {
    aws = {}
    clumio = {
      source  = "clumio-code/clumio"
      version = ">=0.19.0, <0.21.0"
    }
  }
}
