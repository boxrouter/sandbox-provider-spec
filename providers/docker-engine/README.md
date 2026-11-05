# Docker Engine

The driver uses the Docker SDK for Python and the Engine API directly. It requires an
installed, running Docker Engine with permission to access its socket. No provider
account is needed. Docker Desktop's Linux engine is also usable.

The current declaration covers only values with passing evidence for the local
`default` class. The 2026-10-03 baseline report has 16 passing tests and one
unsupported test: `baseline.no_metadata`, because Docker exec has no native guest
command deadline. Its baseline status is `unsupported`. A clean report means owned
run resources were cleaned up; it does not mean the baseline passed. The driver also
does not implement the native `files.remove` operation, which is not claimed.

Before a run, check that your user can reach the Docker daemon with `docker info`.
If every test reports `DockerException`, check that the daemon is running, your user can
access its socket, and the SDK connection settings (`DOCKER_HOST`, `DOCKER_TLS_VERIFY` and
`DOCKER_CERT_PATH`) match your Docker environment. The exception can also indicate a
connection configuration problem, even when `docker info` succeeds.

From a clean checkout, install the optional SDK and run the shared suite:

```sh
uv sync --extra docker
uv run --extra docker sandbox-provider-spec run docker_engine --suite core \
  --fixtures /path/to/provider-fixtures.json --live \
  --output /tmp/docker-engine-core-report.json
uv run --extra docker sandbox-provider-spec run docker_engine --suite coverage \
  --fixtures /path/to/provider-fixtures.json --live \
  --output /tmp/docker-engine-coverage-report.json
```

Both runs need the same flat JSON fixture file. Supply `reachable_url`, an unauthenticated
HTTPS URL reachable from both the runner and the container, for the outbound-network
baseline test.
Without it that test is `not_run`, not a passing baseline. Add fixtures for the selected
coverage tests from the [conformance guide](../../spec/conformance.md#running-the-tests-against-a-provider).

The SDK uses its standard `DOCKER_HOST`, `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH`
configuration. Keep that configuration and fixture files outside the repository.
A fixture `docker_image` selects the default Linux image; otherwise the driver uses
`python:3.12-slim`. Existing images are borrowed. Newly pulled images, created images,
containers and volumes are owned and removed. A shared image still in use makes cleanup
fail rather than forcing another user's image removal.

Dockerfile builds need the external fixture `docker_engine_exclusive_daemon: true` on a
daemon used only by this run. The driver can then attribute and remove newly created base
and intermediate images as well as the final image, including failed builds. It skips
these builds on a shared daemon and never prunes unrelated images or build caches.

A result of `unsupported` is expected where the Engine API has no native operation:
container lifetime and idle timers, individual exec cancellation or reattachment, file
removal, hosted preview credentials and hidden egress secrets. The driver adds no guest
helper to fill these gaps. Filesystem reads and writes use native tar-archive APIs;
unpacking an archive and framing bytes are mechanical conversions.

The declaration cites the shared Linux kernel boundary and leaves unverified modes
and host-specific limits unknown. Passing individual gate tests does not establish a
passing baseline. A missing daemon or socket permission produces `error`, not a claim
that the Engine lacks a capability. See [`evidence.md`](evidence.md) and the saved
[run reports](reports/) for the result details and limits.
