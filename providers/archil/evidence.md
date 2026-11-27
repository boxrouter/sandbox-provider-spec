# Archil provider evidence

The declaration records Archil's documented persistent sandbox contract. Its values have not yet
been verified against a sandbox created with a customer API key. The package currently has only
offline adapter tests; no Archil sandbox was created during this integration work.

Archil's public documentation identifies dedicated Firecracker microVMs, x86-64, 1–32 vCPU,
0.25–64 GiB, a 24-hour session limit, pause/resume with memory intact, and persistent root disks:
[Persistent sandboxes](https://docs.archil.com/compute/sandboxes/introduction). The listed AWS
compute regions are documented in [Region availability](https://docs.archil.com/reference/regions).
The user's console screenshot shows an Enterprise account and its available `aws-us-east-1` region.
The pinned Python SDK documentation states that timeout expiry pauses by default and supports
`on_timeout="delete"` to delete the sandbox and its disk: [archil 0.23.0](https://pypi.org/project/archil/0.23.0/).

BoxRouter already uses Archil in its volume subsystem with BoxRouter-managed regional credentials.
Those credentials are not customer BYOK credentials and are not used by this sandbox adapter.

Before making this provider available to customers, run the SPS tester with the customer's
approved Archil account, verify usage finalization and file/process limits, and confirm that the
account's terms authorize BoxRouter to operate customer-delegated compute.

## Disk

The [Billing page](https://docs.archil.com/administration/billing) lists a maximum size per disk of
10 GB on Free and Unlimited on Developer, Team and Enterprise, so the documentation gives no finite
root disk for a paid plan. A sandbox of each declared size was created on the Enterprise account in
`aws-us-east-1` on 2026-11-27 from the pinned standard image, measured, and deleted at once. All six
(1 vCPU / 2,048 MiB up to 32 vCPU / 65,536 MiB) showed the same ext4 root filesystem,
`/dev/mapper/archil-root`, with `df -m /` reporting 1,031,019 MiB in total and 978,143 MiB free. The
declared `disk_mib` is that observed size, shared by every size; it is not a documented cap, and a
Free account (10 GB) gets less.
