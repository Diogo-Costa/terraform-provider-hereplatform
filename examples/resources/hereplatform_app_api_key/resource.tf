resource "hereplatform_app" "example" {
  name = "example-web"
}

resource "hereplatform_app_api_key" "example" {
  app_hrn    = hereplatform_app.example.hrn
  name       = "example-web-browser"
  expires_at = "2030-01-01T00:00:00Z"
}

# The plaintext key, to hand over to a secret store.
output "example_api_key" {
  value     = hereplatform_app_api_key.example.value
  sensitive = true
}
