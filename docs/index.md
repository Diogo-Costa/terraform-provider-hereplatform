---
page_title: "HERE platform Provider"
description: |-
  Manages HERE platform identity and access management: apps, API keys and trusted domains.
---

# HERE platform Provider

Manages HERE platform identity and access management: apps, API keys and trusted domains.

The provider calls the HERE Authentication API v1.1 as an *automation app*: a HERE platform app whose
credentials Terraform uses. HERE grants the automation app manage permission on the apps it creates.

The provider requires Terraform 1.3 or later, which lets it check `deletion_protection` at plan time.

## Bootstrap

A human Org Admin prepares the automation app once:

1. Create the app in the HERE platform portal.
2. Enable app creation for it (`appCreationEnabled`), so it can create other apps.
3. Detach the `restricted-iam-access` access filter, which HERE attaches to every new app and which
   blocks the creation of IAM resources such as apps. Make sure the app does not hold the
   *Restricted App Access* role.
4. Register a public JWK on the app (recommended), or create an access key for it.
5. Make the app a manager of every pre-existing app it must adopt or look up: HERE lists and reads
   only the apps the caller has permissions on.

## Authentication

Configure exactly one method. Every argument also has a `HERE_*` environment variable, and the
values of a HERE `credentials.properties` file can be used through `credentials_file`.

* **OAuth 2.1 `private_key_jwt` (recommended)**: `client_id` and `private_key`, plus `key_id` when
  the registered JWK has a `kid`. The provider signs a short-lived RS256 client assertion for each
  token request, so no shared secret leaves the machine.
* **Access key (OAuth 1.0)**: `access_key_id` and `access_key_secret`, such as the values of a
  downloaded `credentials.properties` file.

When both methods are complete, `private_key_jwt` is used. Tokens are requested without a scope,
because the identity endpoints reject project-scoped tokens, with a one-hour lifetime, and are cached
and refreshed before they expire.

Prefer the environment variables, with an empty `provider "hereplatform" {}` block, to arguments:
unlike input variables, they never end up in saved plan files.

## Example Usage

```terraform
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
```

Pin the provider version, as above, and commit the `.terraform.lock.hcl` file that `terraform init`
writes, so every run installs the same checksum-verified build.

## Behaviour and limits

* HERE IAM is eventually consistent for up to about five minutes. The provider retries throttled
  (HTTP 429) and transient errors, and waits after each change until reads reflect it, within the
  resource timeouts.
* An app can have at most two API keys.
* Trusted domain changes can take up to 30 minutes to be enforced. While enforcement is off, HERE
  accepts the app's API keys from any origin.
* A request that creates an app or an API key runs to completion once sent, for up to the 60-second
  HTTP timeout, even when `timeouts.create` expires or Terraform is interrupted, so HERE's answer is
  never lost. An apply can therefore exceed `timeouts.create` by up to that much.
* HERE may apply a create whose response is lost: on a dropped connection, a server error or the
  HTTP timeout. The provider does not retry such a create and fails instead: check HERE, and import
  the object if it exists or apply again if it does not.

## Deletion protection

Deleting an app or an API key is permanent, and deleting a trusted domain configuration turns its
enforcement off. All three resources therefore have `deletion_protection`, which defaults to `true`,
also after import:

* A plan that destroys a protected resource fails, and so does a plan that replaces a protected API
  key or trusted domain configuration. Nothing is deleted, including the resources that depend on it.
* To delete a resource, set `deletion_protection = false` and apply, and then remove it from the
  configuration or destroy it.
* To stop managing a resource without changing HERE, use a `removed` block with
  `lifecycle { destroy = false }` (Terraform 1.7 or later), or `terraform state rm`.
* Terraform plans the replacement of a tainted resource, or of one targeted by `-replace` or
  `replace_triggered_by`, as a create, so the provider can only stop it when the delete is applied.
  To keep the resource, run `terraform untaint`, or plan again without `-replace`.

To rotate an API key without an outage, add a second `hereplatform_app_api_key` to the app and
apply, switch the clients to the new key, set `deletion_protection = false` on the old key and
apply, and then remove the old key.

## Security

* `hereplatform_app_api_key.value` holds the plaintext API key. It is stored in the state and in
  saved plan files (`terraform plan -out`), which also hold the values of input variables. Treat
  both as secrets: restrict access to the state backend, and do not keep plan files as CI artifacts.
* Keep credentials in the environment, or in a `credentials.properties` file that only its owner can
  access. The provider warns when other users can access the file.
* `token_url` and `api_url` receive credentials, so only HERE and loopback addresses are accepted,
  unless `HERE_ALLOW_CUSTOM_ENDPOINTS=1` is set in the environment.
* `TF_LOG=DEBUG` logs each HERE request's method, path, status and correlation ID, never tokens,
  keys, secrets or bodies. `TF_LOG_SDK_PROTO_DATA_DIR`, by contrast, makes the plugin libraries write
  every raw message from Terraform to disk, including the provider configuration, plans and state
  with their secrets: never set it in CI or on a shared machine.

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `access_key_id` (String) Access key ID for OAuth 1.0 client authentication. Defaults to `HERE_ACCESS_KEY_ID`, then to `here.access.key.id` in `credentials_file`.
- `access_key_secret` (String, Sensitive) Access key secret for OAuth 1.0 client authentication. Defaults to `HERE_ACCESS_KEY_SECRET`, then to `here.access.key.secret` in `credentials_file`.
- `api_url` (String) Base URL of the HERE Authentication API v1.1. Defaults to `HERE_API_URL`, then to `https://account.api.here.com/authentication/v1.1`. Only HTTPS URLs of `account.api.here.com` are accepted, plus HTTP or HTTPS URLs of literal loopback IP addresses for test servers. Other HTTPS hosts require `HERE_ALLOW_CUSTOM_ENDPOINTS=1` in the environment, which no configuration can set, and produce a warning.
- `client_id` (String) Client ID of the HERE app the provider authenticates as with OAuth 2.1 `private_key_jwt`. Defaults to `HERE_CLIENT_ID`, then to `here.client.id` in `credentials_file`.
- `credentials_file` (String) Path to a HERE `credentials.properties` file. Defaults to `HERE_CREDENTIALS_FILE`. The provider warns when other users can access the file.
- `key_id` (String) `kid` of the registered JWK, sent in the client assertion header. Optional but recommended by HERE: without it, the provider warns. Defaults to `HERE_KEY_ID`.
- `private_key` (String, Sensitive) PEM-encoded RSA private key (PKCS #1 or PKCS #8, at least 2048 bits) matching a JWK registered on the app. Defaults to `HERE_PRIVATE_KEY`.
- `token_url` (String) OAuth token endpoint. Defaults to `HERE_TOKEN_URL`, then to `here.token.endpoint.url` in `credentials_file`, then to `https://account.api.here.com/oauth2/token`. Only HTTPS URLs of `account.api.here.com` are accepted, plus HTTP or HTTPS URLs of literal loopback IP addresses for test servers. Other HTTPS hosts require `HERE_ALLOW_CUSTOM_ENDPOINTS=1` in the environment, which no configuration can set, and produce a warning.
