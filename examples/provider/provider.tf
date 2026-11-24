terraform {
  # 1.3 or later checks deletion_protection at plan time.
  required_version = ">= 1.3"

  required_providers {
    hereplatform = {
      source  = "Diogo-Costa/hereplatform"
      version = "~> 0.1"
    }
  }
}

# Credentials come from the environment: HERE_CLIENT_ID, HERE_PRIVATE_KEY and
# HERE_KEY_ID for private_key_jwt, or HERE_ACCESS_KEY_ID and HERE_ACCESS_KEY_SECRET
# for an access key. Unlike input variables, they never end up in saved plan files.
provider "hereplatform" {}
