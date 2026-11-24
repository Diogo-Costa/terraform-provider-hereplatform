# Terraform Provider for HERE platform

Terraform provider for [HERE platform](https://platform.here.com) identity and access management:
apps, API keys and trusted domains.

> **Status:** pre-release. Version 0.1.0 is under review and not yet published to the Terraform Registry.

## What it manages

| Type | Name | Purpose |
|---|---|---|
| Resource | `hereplatform_app` | A HERE app: the identity that owns OAuth credentials and API keys. |
| Resource | `hereplatform_app_api_key` | An API key of an app, including its plaintext value. |
| Resource | `hereplatform_app_trusted_domains` | The trusted domains of an app and whether HERE enforces them. |
| Data source | `hereplatform_app` | Looks an app up by HRN or by exact name. |

The provider calls the HERE Authentication API v1.1. Full documentation lives in [`docs/`](docs/), and
runnable configurations in [`examples/`](examples/).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/install) 1.0 or later (plugin protocol v6).
- [Go](https://go.dev/doc/install) at the version in [`go.mod`](go.mod), to build from source.

## Prerequisites

Terraform authenticates as an *automation app*. A human Org Admin prepares it once:

1. Create the automation app in the HERE platform portal.
2. Enable app creation for it (`appCreationEnabled`), so it can create other apps.
3. Detach the `restricted-iam-access` access filter. HERE attaches it to every new app, and it blocks
   the creation of IAM resources such as apps. The automation app must not hold the
   *Restricted App Access* role either.
4. Register a public JWK on the app (recommended), or create an access key for it.
5. Make the automation app a manager of every pre-existing app it must adopt or look up. HERE lists
   and reads only the apps the caller has permissions on, so other apps look missing.

Apps the automation app creates grant it manage permission automatically. They start with the
`restricted-iam-access` filter attached, which suits apps that only call HERE services.

## Authentication

Configure exactly one method. Each argument falls back to an environment variable, and the access
key, client ID and token URL can also come from a HERE `credentials.properties` file.

| Argument | Environment variable | Notes |
|---|---|---|
| `client_id` | `HERE_CLIENT_ID` | `private_key_jwt`: client ID of the automation app. |
| `private_key` | `HERE_PRIVATE_KEY` | `private_key_jwt`: PEM-encoded RSA key (2048 bits or more) matching the registered JWK. Sensitive. |
| `key_id` | `HERE_KEY_ID` | `private_key_jwt`: `kid` of the registered JWK. Optional, recommended. |
| `access_key_id` | `HERE_ACCESS_KEY_ID` | Access key (OAuth 1.0). |
| `access_key_secret` | `HERE_ACCESS_KEY_SECRET` | Access key (OAuth 1.0). Sensitive. |
| `credentials_file` | `HERE_CREDENTIALS_FILE` | Path to a `credentials.properties` file. |
| `token_url` | `HERE_TOKEN_URL` | Defaults to `https://account.api.here.com/oauth2/token`. |
| `api_url` | `HERE_API_URL` | Defaults to `https://account.api.here.com/authentication/v1.1`. |

- **OAuth 2.1 `private_key_jwt` (recommended):** the provider signs a short-lived RS256 client
  assertion per token request, so no shared secret is sent.
- **Access key (OAuth 1.0):** HMAC-SHA256 signed token requests.

When both methods are complete, `private_key_jwt` wins. Tokens are requested without a scope,
because the identity endpoints reject project-scoped tokens, and are cached until shortly before
they expire.

## Usage

```terraform
terraform {
  required_providers {
    hereplatform = {
      source = "Diogo-Costa/hereplatform"
    }
  }
}

# Credentials come from HERE_CLIENT_ID, HERE_PRIVATE_KEY and HERE_KEY_ID.
provider "hereplatform" {}

resource "hereplatform_app" "web" {
  name        = "example-web"
  description = "Browser client of the example service."
}

resource "hereplatform_app_api_key" "web" {
  app_hrn = hereplatform_app.web.hrn
  name    = "example-web-browser"
}

resource "hereplatform_app_trusted_domains" "web" {
  app_hrn = hereplatform_app.web.hrn
  domains = ["example.com"]
}
```

### Import

| Resource | Import ID |
|---|---|
| `hereplatform_app` | App HRN, such as `hrn:here:account::myrealm:app/AbCdEfGhIjKlMnOpQrSt` |
| `hereplatform_app_api_key` | `<app_hrn>,<apikey_hrn>`, because HERE reads keys only through their app |
| `hereplatform_app_trusted_domains` | App HRN |

## Behaviour and limits

- **Eventual consistency.** HERE IAM can take about five minutes to reflect a change. The provider
  retries throttled (HTTP 429) and transient errors with backoff, and after each change waits until
  reads reflect it, within the resource `timeouts`.
- **Two API keys per app.** Creating a third fails with HERE error 409303. A replaced key is deleted
  first and can count for a few minutes, so creation retries within its timeout.
- **Trusted domains** take up to 30 minutes to be enforced. The resource is authoritative: it removes
  entries of the app that are not in `domains`.
- **Deletes are permanent.** Deleting an app revokes all of its credentials, so `hereplatform_app`
  has `deletion_protection`, on by default: set it to `false` and apply before destroying an app.
- **Secrets in state.** `hereplatform_app_api_key.value` holds the plaintext API key. Treat the
  Terraform state as secret.

## Development

| Command | Purpose |
|---|---|
| `make build` | Build the provider. |
| `make install` | Install the provider binary into `$GOPATH/bin`. |
| `make lint` | Run golangci-lint. |
| `make test` | Run the unit tests. Some drive the Terraform CLI through terraform-plugin-testing. |
| `make testacc` | Run the acceptance tests against a real HERE realm. |
| `make docs` | Format the examples and regenerate `docs/` with tfplugindocs. |

Acceptance tests create and delete real apps: run them only against a sandbox realm, with the
`HERE_*` variables of a dedicated automation app. Test resources are named with the `tfacc-` prefix.

To try a local build, point Terraform at it with a
[development override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers):

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/Diogo-Costa/hereplatform" = "/path/to/go/bin"
  }
  direct {}
}
```

`TF_LOG=DEBUG` logs each HERE request's method, path, status and correlation ID. Tokens, keys,
secrets and request or response bodies are never logged.

## License

[GPL-3.0](LICENSE)
