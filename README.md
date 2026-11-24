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

- [Terraform](https://developer.hashicorp.com/terraform/install) 1.3 or later. Earlier versions check
  `deletion_protection` only while they apply a delete, after the resources that depend on it may be
  gone, and the provider warns about it. `removed` blocks need Terraform 1.7 or later.
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
| `key_id` | `HERE_KEY_ID` | `private_key_jwt`: `kid` of the registered JWK. Optional, recommended: the provider warns without it. |
| `access_key_id` | `HERE_ACCESS_KEY_ID` | Access key (OAuth 1.0). |
| `access_key_secret` | `HERE_ACCESS_KEY_SECRET` | Access key (OAuth 1.0). Sensitive. |
| `credentials_file` | `HERE_CREDENTIALS_FILE` | Path to a `credentials.properties` file. The provider warns when other users can access it. |
| `token_url` | `HERE_TOKEN_URL` | Defaults to `https://account.api.here.com/oauth2/token`. |
| `api_url` | `HERE_API_URL` | Defaults to `https://account.api.here.com/authentication/v1.1`. |

`token_url` and `api_url` accept only `account.api.here.com`, plus literal loopback IP addresses for
test servers, because both receive credentials. To use another HTTPS host, set
`HERE_ALLOW_CUSTOM_ENDPOINTS=1` in Terraform's environment; no configuration can, and the provider
warns on every run while it is in use.

- **OAuth 2.1 `private_key_jwt` (recommended):** the provider signs a short-lived RS256 client
  assertion per token request, so no shared secret is sent.
- **Access key (OAuth 1.0):** HMAC-SHA256 signed token requests.

When both methods are complete, `private_key_jwt` wins. Tokens are requested without a scope,
because the identity endpoints reject project-scoped tokens, with a one-hour lifetime, and are
cached until shortly before they expire.

Prefer the environment variables, with an empty `provider "hereplatform" {}` block, to arguments:
unlike input variables, they never end up in saved plan files.

## Usage

```terraform
terraform {
  required_version = ">= 1.3"

  required_providers {
    hereplatform = {
      source  = "Diogo-Costa/hereplatform"
      version = "~> 0.1"
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

Pin the provider version, as above, and commit the `.terraform.lock.hcl` file that `terraform init`
writes, so every run installs the same checksum-verified build.

### Import

Import with an `import` block (Terraform 1.5 or later) or `terraform import`:

| Resource | Import ID |
|---|---|
| `hereplatform_app` | App HRN, such as `hrn:here:account::myrealm:app/AbCdEfGhIjKlMnOpQrSt` |
| `hereplatform_app_api_key` | `<app_hrn>,<apikey_hrn>`, because HERE reads keys only through their app |
| `hereplatform_app_trusted_domains` | App HRN |

Imported resources start with `deletion_protection = true`. Before you import an app that creates
other apps, such as the automation app itself, set `app_creation_enabled = true` in its
configuration: otherwise the next apply turns its app creation off.

## Behaviour and limits

- **Eventual consistency.** HERE IAM can take about five minutes to reflect a change. The provider
  retries throttled (HTTP 429) and transient errors with backoff, and after each change waits until
  reads reflect it, within the resource `timeouts`.
- **Two API keys per app.** Creating a third fails with HERE error 409303. A replaced key is deleted
  first and can count for a few minutes, so creation retries within its timeout.
- **Trusted domains** take up to 30 minutes to be enforced. The resource is authoritative: it removes
  entries of the app that are not in `domains`. While enforcement is off, after `enabled = false` or
  once the resource is deleted, HERE accepts the app's API keys from any origin; plans that turn it
  off show a warning.
- **Unconfirmed creates.** HERE may apply a create whose response is lost, for example on a timeout
  or a server error. The provider does not retry such a create, which could make a second app or
  take the last of an app's two key slots, and fails instead: check HERE, and import the object if
  it exists or apply again if it does not.

## Deletion protection

HERE deletes apps and API keys permanently, and deleting an app revokes all of its credentials.
Deleting a trusted domain configuration turns its enforcement off. All three resources therefore
have `deletion_protection`, which defaults to `true`, also after import:

- A plan that destroys a protected resource fails, and so does a plan that replaces a protected API
  key or trusted domain configuration. Nothing is deleted, including the resources that depend on it.
- To delete a resource, set `deletion_protection = false` and apply, and then remove it from the
  configuration or destroy it.
- To stop managing a resource without changing HERE, use a `removed` block with
  `lifecycle { destroy = false }`, or `terraform state rm`.
- Terraform plans the replacement of a tainted resource, or of one targeted by `-replace` or
  `replace_triggered_by`, as a create, so the provider can only stop it when the delete is applied.
  To keep the resource, run `terraform untaint`, or plan again without `-replace`.

To rotate an API key without an outage:

1. Add a second `hereplatform_app_api_key` to the app, and apply. HERE allows two per app.
2. Switch the clients to the new key.
3. Set `deletion_protection = false` on the old key, and apply.
4. Remove the old key from the configuration, and apply.

## Security

- **Secrets in state and plans.** `hereplatform_app_api_key.value` holds the plaintext API key. It is
  stored in the state and in saved plan files (`terraform plan -out`), which also hold the values of
  input variables. Treat both as secrets: restrict access to the state backend, and do not keep plan
  files as CI artifacts.
- **Credentials.** Keep them in the environment, or in a `credentials.properties` file that only its
  owner can access (`chmod 600`).
- **Endpoints.** `token_url` and `api_url` receive credentials, so only HERE and loopback addresses
  are accepted, unless `HERE_ALLOW_CUSTOM_ENDPOINTS=1` is set.
- **Logs.** `TF_LOG=DEBUG` logs each HERE request's method, path, status and correlation ID. Tokens,
  keys, secrets and request or response bodies are never logged. `TF_LOG_SDK_PROTO_DATA_DIR`, by
  contrast, makes the plugin libraries write every raw message from Terraform to disk, including the
  provider configuration, plans and state with their secrets: never set it in CI or on a shared
  machine.

## Development

| Command | Purpose |
|---|---|
| `make build` | Build the provider. |
| `make install` | Install the provider binary into `$GOPATH/bin`. |
| `make lint` | Run golangci-lint. |
| `make test` | Run the unit tests. Some drive the Terraform CLI through terraform-plugin-testing. |
| `make testacc` | Run the acceptance tests against a real HERE realm. |
| `make sweep` | Delete the `tfacc-` apps that interrupted acceptance runs left behind. |
| `make docs` | Format the examples and regenerate `docs/` with tfplugindocs. |

Acceptance tests create and delete real apps: run them only against a sandbox realm, with the
`HERE_*` variables of a dedicated automation app. Test resources are named with the `tfacc-` prefix.

In CI, the acceptance job runs in the `acceptance` environment, which holds the `HERE_*` secrets and
requires an approval for each run. It runs on manual dispatches, and on pushes and pull requests
from this repository when the repository variable `RUN_ACCEPTANCE_TESTS` is `true`; never for forks.
Runs are serialized, and each ends with a sweep. Releases run from `v*` tags on `main`, in the
`release` environment.

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

## License

[GPL-3.0](LICENSE)
