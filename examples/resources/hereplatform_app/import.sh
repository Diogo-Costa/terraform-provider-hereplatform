# Apps are imported by HRN. Imported apps start with deletion_protection = true.
# Before importing an app that creates other apps, such as the provider's own app,
# set app_creation_enabled = true: otherwise the next apply turns app creation off.
terraform import hereplatform_app.example "hrn:here:account::myrealm:app/AbCdEfGhIjKlMnOpQrSt"
