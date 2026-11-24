terraform {
  required_providers {
    hereplatform = {
      source = "Diogo-Costa/hereplatform"
    }
  }
}

# Authenticates with OAuth 2.1 private_key_jwt. Each argument can come from the
# environment instead (HERE_CLIENT_ID, HERE_PRIVATE_KEY, HERE_KEY_ID), so an empty
# provider block is enough in CI.
provider "hereplatform" {
  client_id   = var.here_client_id
  private_key = var.here_private_key
  key_id      = var.here_key_id
}

variable "here_client_id" {
  description = "Client ID of the automation app."
  type        = string
}

variable "here_private_key" {
  description = "PEM-encoded RSA private key whose public JWK is registered on the automation app."
  type        = string
  sensitive   = true
}

variable "here_key_id" {
  description = "kid of the registered JWK."
  type        = string
  default     = null
}
