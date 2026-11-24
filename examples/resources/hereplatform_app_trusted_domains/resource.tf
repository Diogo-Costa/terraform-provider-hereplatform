resource "hereplatform_app" "example" {
  name = "example-web"
}

resource "hereplatform_app_trusted_domains" "example" {
  app_hrn = hereplatform_app.example.hrn

  # A bare domain also matches its subdomains, any scheme and any port.
  domains = [
    "example.com",
    "https://maps.example.org:8443/viewer",
    "192.0.2.10",
  ]
}
