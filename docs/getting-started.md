# Check a request and interpret a match

In this tutorial you will validate a workload request, compare two bundled declarations,
and understand why a valid declaration can still be refused. No provider account, SDK,
Docker daemon, or sandbox is needed. After installation, these commands work offline.

## Install

Use Python 3.11 or newer and the [README installation block](../README.md#development).
Before publication, run that block from the root of a source checkout. You can obtain the
source with Git:

```sh
git clone https://github.com/boxrouter/sandbox-provider-spec.git
cd sandbox-provider-spec
```

Until the repository is public, use a checkout or source archive supplied by a maintainer.
Installation uses only the public Python index for dependencies. It does not need any
provider credentials.

If Python reports that `ensurepip` is unavailable, install your system's `python3-venv`
package, or use [uv](https://docs.astral.sh/uv/) to replace the incomplete environment left
by the failed command:

```sh
uv venv --clear --python 3.11 --seed .venv
. .venv/bin/activate
```

Then run the installation command from the README inside that environment.

The README is the single installation entry point; all steps below also work with the
installed package from any directory, including one outside the source checkout.

## Describe your workload

Save this as `request.yaml`. It asks for the optional ability to control background processes:

```yaml
requirements:
  processes: {}
```

```console
$ sandbox-provider-spec check request.yaml
request.yaml: ok
```

Exit 0 means the request follows the format. It has not run anything or proved that a
provider satisfies it.

## Compare declarations

The package includes declarations and their cited reports. Find a declaration using
`sandbox-provider-spec installed-declaration docker-engine`; the command prints its absolute path.
Use that path with `match`, as in the [checked README transcript](../README.md#the-matching-result).
Paths discovered this way work with both a source install and a wheel install.

`match` prints `eligible` or `not eligible` for each provider or execution class, followed
by reasons for every refusal. Exit 0 means at least one qualifies; exit 1 means none
qualifies or an input was refused. Neither result creates a sandbox or contacts a provider.

## Read a refusal

`baseline_failed` means the current reports do not establish the behavior every provider
must supply. A clean report describes confirmed cleanup; it can still contain failed,
unsupported, or unrun tests. The bundled Docker Engine reference intentionally exposes a
baseline limitation: its SDK cannot enforce the required command deadline.

Other common reasons:

| Reason | What to inspect |
| --- | --- |
| `gate_not_listed` | The declaration has no claim for the requested optional feature. |
| `knob_mismatch` | A claimed feature has different details than the request requires. |
| `resource_unknown` | A required resource fact is unknown. Unknown values never establish support. |
| `limit_exceeded` | A declared limit does not establish enough capacity for the request. |
| `gate_unavailable` | A declared prerequisite is not known to hold; see the matcher's exact reason. |

Keep requirements your program needs. To investigate a refusal, [inspect the cited evidence](how-to/read-evidence.md).
To try a larger workload, copy a request from the source checkout's
[`examples/requests` directory](https://github.com/boxrouter/sandbox-provider-spec/tree/main/examples/requests)
and save it locally, then
[compare more providers](how-to/compare-providers.md).
