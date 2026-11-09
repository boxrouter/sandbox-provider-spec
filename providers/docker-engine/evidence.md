# Docker Engine evidence

The Docker Engine reference uses a local installation and no provider account.
The declaration describes only the `default` execution class and Docker SDK 7.2.0.
All reports below bind to a single source revision and were produced on Docker Engine
running in Colima on macOS; the engine version was not recorded. Each report is `clean: true`: its
cleanup ledger shows every resource the run created released.

## Live evidence

The declaration's tested values come from
[`2026-10-03-core.json`](reports/2026-10-03-core.json):

- `resources.default_user: root` and `resources.default_cwd: /` passed.
- Process cancellation and reattachment set to `false` passed.
- Pause/resume preserving files only and files plus memory passed.
- File-only snapshots and snapshot deletion passed.
- Filesystem volumes with many writers passed.
- Dockerfile custom-image builds passed with the exclusive-daemon fixture enabled.

That core run selected 102 tests: 33 passed, 32 were unsupported, 29 were not run,
4 differed, and 4 errored. Only passing probes support declaration values.

The explicit baseline report
[`2026-10-03-baseline-mirror.json`](reports/2026-10-03-baseline-mirror.json)
selected 17 tests: 16 passed and `baseline.no_metadata` was unsupported because
Docker exec has no native guest-command deadline. The report's baseline status is
`unsupported`; this is not a passing baseline.

The all-mirrors coverage report
[`2026-10-03-coverage-all-mirrors.json`](reports/2026-10-03-coverage-all-mirrors.json)
selected 116 tests: 19 passed, 62 were unsupported, 34 were not run, one differed,
and none errored. Earlier runs hit Docker Hub's anonymous-pull limit; the final
run used equivalent Docker Official Images from [Amazon ECR Public Python](https://gallery.ecr.aws/docker/library/python)
and [Amazon ECR Public Ubuntu](https://gallery.ecr.aws/docker/library/ubuntu) as
local image mirrors. This resolved the pull and image-build errors. Other dated
reports retain the original baseline and diagnostic attempts.

The shared-kernel declaration is supported by Docker's documentation, read
2026-09-30: [Multi-platform builds](https://docs.docker.com/build/building/multi-platform/)
says containers share the host kernel.

## Not proven

- The default class has no passing full baseline: `baseline.no_metadata` is
  unsupported because the Engine API offers no native guest-command deadline.
  This result does not establish a general baseline failure or a claim for another
  execution class.
- `coverage.volumes.read_only` differs on stdout. The saved run records actual
  stdout `seed` (`c2VlZA==`) and exit code 0, but the suite at that revision expected
  `seed\n`, a defect in the test since fixed: [`conformance/coverage.yaml`](../../conformance/coverage.yaml)
  now expects `seed`. The later write-denial steps were not reached, so read-only
  enforcement stays unproven, and `volumes.read_only_mounts` undeclared, until a rerun.
- `coverage.docker.bridge` and `coverage.docker.host` are unsupported because the
  Engine API has no native container lifetime timer. No Docker networking value is
  claimed.
- The driver does not implement the native `files.remove` operation. This is a
  separate unclaimed operation and is not the reported cause of the baseline's
  unsupported status.
- Missing endpoint fixtures leave endpoint-dependent network, preview, secret,
  proxy and port behavior unproven. Unsupported, differing, errored, and not-run
  probes in the saved reports establish no declaration values.
- Only the `default` local execution class was run. Other execution classes and
  the remaining unknown resource limits, locations, regions and lifetime behavior
  are unproven.
