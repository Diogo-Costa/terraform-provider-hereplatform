data "hereplatform_app" "by_hrn" {
  hrn = "hrn:here:account::myrealm:app/AbCdEfGhIjKlMnOpQrSt"
}

# Name lookups only see the apps the provider's identity has permissions on.
data "hereplatform_app" "by_name" {
  name = "example-service"
}

output "example_client_id" {
  value = data.hereplatform_app.by_name.client_id
}
