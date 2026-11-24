# API keys are imported by "<app_hrn>,<apikey_hrn>", because HERE reads keys only
# through their app. The plaintext value is recovered on import, and imported keys
# start with deletion_protection = true.
terraform import hereplatform_app_api_key.example "hrn:here:account::myrealm:app/AbCdEfGhIjKlMnOpQrSt,hrn:here:account::myrealm:apikey/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-AbCd"
