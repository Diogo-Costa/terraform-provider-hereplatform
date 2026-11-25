# Changelog

## 0.1.0

NOTES:

- First release. The provider calls the HERE Authentication API v1.1, and needs Terraform 1.3 or
  later to check `deletion_protection` at plan time.
- The state and saved plan files hold the plaintext value of every managed API key: treat both as
  secrets.

FEATURES:

- **New Resource:** `hereplatform_app`. A rename updates the app in place and keeps its HRN and
  credentials.
- **New Resource:** `hereplatform_app_api_key`, with `enabled` and an optional `expires_at`.
- **New Resource:** `hereplatform_app_trusted_domains`: the trusted domains of an app, and whether
  HERE enforces them.
- **New Data Source:** `hereplatform_app`, looked up by HRN or by exact name.
- Authentication with OAuth 2.1 `private_key_jwt` (recommended) or an access key (OAuth 1.0), from
  arguments, `HERE_*` environment variables or a `credentials.properties` file. Tokens are
  requested without a scope, last one hour and are cached.
- `deletion_protection` on all three resources, `true` by default and after import: a plan that
  destroys a protected resource fails before anything is deleted.
- Import of apps and trusted domains by app HRN, and of API keys by `<app_hrn>,<apikey_hrn>`. An
  imported key's plaintext value is recovered.
- `token_url` and `api_url` accept only `account.api.here.com` and literal loopback IP addresses,
  unless `HERE_ALLOW_CUSTOM_ENDPOINTS=1` is set.
- Retries with backoff on throttling (HTTP 429) and transient errors, and waits for HERE's eventual
  consistency within the resource `timeouts`. A create already sent runs to completion, for up to
  the 60-second HTTP timeout, and a create whose answer is lost is reported, never retried.
- Logs never include tokens, keys, secrets or request and response bodies.
