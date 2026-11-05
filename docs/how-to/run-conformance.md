# Run conformance

The [first tutorial](../getting-started.md) works entirely offline. Running conformance
instead creates resources through a provider's SDK. Cloud providers need your own account
and may charge for them. Docker Engine needs a running engine and no provider account.

Use a source checkout, [uv](https://docs.astral.sh/uv/), and the SDK extra for the chosen
driver. Read the [fixture tables](../../spec/conformance.md#running-the-tests-against-a-provider)
and [driver notes](../../spec/conformance.md#driver-notes) before running either suite.
Missing fixtures yield `not_run`, which is not a pass. An HTTP provider uses
[the HTTP suite command](run-http-conformance.md) instead of the native CLI below.

For Docker, first check `docker info`. Choose an HTTPS endpoint that both the runner and
the sandbox can reach directly. `https://example.com/` is an illustration, not a tested
fixture: export `SPS_REACHABLE_URL` with your reachable endpoint and verify direct HTTPS
reachability from both places before each run. Replace it if either check fails.
Keep fixtures and output outside the checkout:

```sh
run_dir=$(mktemp -d)
python -c 'import json, os; print(json.dumps({"reachable_url": os.environ["SPS_REACHABLE_URL"]}))' > "$run_dir/fixtures.json"
for suite in core coverage; do
  uv run --extra docker sandbox-provider-spec run docker_engine --suite "$suite" --live \
    --fixtures "$run_dir/fixtures.json" --output "$run_dir/$suite.json"
done
```

On a cold daemon, Docker Hub can refuse anonymous image pulls with HTTP 429. Authenticate
with `docker login` or use a cached registry mirror for that daemon before running the
suites; the [README describes the symptoms and remedies](../../README.md#run-docker-conformance).

The runner resolves documented unsupported operations and runs checks without explicit
elapsed-time waits first. Independent single-sandbox timer checks can share elapsed
windows without sharing native handles or observations. Set the runner fixture
`max_live_sandboxes` to a positive integer to bound that overlap; the default is `1`
(serial waits). Keep it at `1` for a one-sandbox workspace, and stay within the account quota
for every run. Checks whose fixtures allocate
additional resources remain serial; their own resource requirements still apply.

The lifetime-extension check has independent `extended` and `control` step lanes.
Each lane has its own bindings and cleanup. Both must pass to prove extension; a
missing operation, failed control or failed extension cannot establish the fact.
At a limit of at least `2`, the lanes share one 305-second window. At `1`, they run
serially, and an unsupported extension stops before the control wait.

The runner attempts cleanup after each test and records the result. Investigate any
unconfirmed cleanup in your own run before treating the report as clean. A clean report
can still contain failed or unsupported tests. Review both reports and follow the
[report-selection and commit rules](../../spec/conformance.md#results-and-reports)
before citing them in a declaration.

The Docker reference currently reports a baseline limitation; running it does not promise
a passing baseline. Its [notes](../../providers/docker-engine/README.md) explain the SDK
behavior. For another provider, use its driver name and SDK environment variables from
the conformance reference; never put credentials in a fixture or committed report.
