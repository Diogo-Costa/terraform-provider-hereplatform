resource "hereplatform_app" "example" {
  name        = "example-service"
  description = "Backend of the example service."
}

# An app allowed to create other apps, such as a deployment pipeline identity.
resource "hereplatform_app" "deployer" {
  name                 = "example-deployer"
  app_creation_enabled = true
}

# Deleting an app is permanent and revokes its credentials: set deletion_protection
# to false and apply before destroying it.
resource "hereplatform_app" "scratch" {
  name                = "example-scratch"
  deletion_protection = false
}
