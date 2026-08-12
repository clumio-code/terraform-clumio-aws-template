variable "clumio_api_token" {
  description = "API Token required to invoke Clumio APIs."
  type        = string
  sensitive   = true
}

variable "clumio_api_base_url" {
  description = "Base URL for Clumio APIs."
  type        = string
}
