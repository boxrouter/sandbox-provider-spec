# Security

## Reporting a vulnerability

Report a vulnerability privately through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability**. If GitHub's private reporting form is unavailable, email
[security@boxrouter.ai](mailto:security@boxrouter.ai). Please do not open a
public issue or pull request for it.

The maintainers will acknowledge the report within 7 days, keep you informed while it is
fixed, and credit you when it is disclosed, unless you prefer otherwise.

## Scope

In scope is the code in this repository: the checker, the conformance runner and the
drivers. Examples are a driver or a run report that could expose a credential, and a check
that accepts a file it should refuse.

A vulnerability in a provider's service or SDK belongs to that provider: report it to them.
If it also makes a declaration here wrong, such as a network lockdown that code in the
sandbox can lift, report that here privately as well. The declaration is corrected once the
provider has had the chance to respond.

## Supported versions

Fixes go into the latest release.
