# Security policy

## Reporting a vulnerability

Report vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://github.com/Diogo-Costa/terraform-provider-hereplatform/security/advisories/new).
Do not open a public issue, pull request or discussion about a suspected vulnerability.

A useful report includes:

- the provider version, and the Terraform or OpenTofu version;
- the affected resource, data source or provider setting;
- the steps to reproduce it, with a minimal configuration;
- the impact you expect.

Never include credentials, API keys, private keys, tokens, state files or saved plan files in a
report: replace them with placeholders. If a real secret was exposed, revoke or rotate it on the HERE
platform first.

Vulnerabilities in the HERE platform itself, rather than in this provider, belong to HERE: report
them to HERE directly.

## What to expect

The provider has a single maintainer, so responses are best effort. The aim is to acknowledge a
report within 7 days, and to share an assessment, with a fix plan if the report is confirmed, within
30 days.

Disclosure is coordinated with the reporter. The advisory is published once a release with the fix
is available, crediting the reporter unless they ask otherwise. Please keep the details private
until then.

## Supported versions

Security fixes are released for the latest version only.

## Scope

In scope: the provider's code, its handling of credentials and secrets, and its release artifacts and
signatures.

Out of scope:

- the secrets that Terraform keeps in state and in saved plan files by design (see
  [Security](README.md#security) in the README);
- vulnerabilities in Terraform, OpenTofu or the HERE platform.
