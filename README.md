# Disposable ARM64 Linux platform smoke

Minimal public repository containing only generic synthetic Linux compatibility probes. There is **no private application source**, company identifier, secret, token, database, receipt, or proprietary harness here.

## Operator gate

* Create a **new** public repository. Keep its default branch `main`, separate from any production repository.
* Before running: independently inspect the exact files; verify the repository contains only this public generic material; confirm GitHub Actions standard public runner usage is free; confirm there are no untrusted collaborators.
* The ONLY supported trigger is manual `workflow_dispatch`, on `main`, with the exact `RUN_SYNTHETIC_ARM64_SMOKE` confirmation, initiated by `hybmo99`.
* 8-minute Actions job hard timeout; 180-second probe timeout; no paid resources, no secrets, no private GitHub checkout, no company credentials. If a platform check fails, STOP and collect the public run logs for review.

## What it checks

1. ARM64 Ubuntu 24.04 runner with PID1 systemd.
2. Availability and **check-only** parsing/kernel validation of `socket cgroupv2` nftables syntax. No firewall rule applied: **NOT an effective egress-deny proof**.
3. One disposable `systemd-run` sleep service with exact Id/ActiveState/MainPID/ControlGroup and `/proc/<pid>/cgroup` agreement, immediately reverified before single PID-targeted SIGKILL. Service cleaned up.

## What it cannot prove

No private harness is executed. This does not verify the real company's deployment, service-specific startup, database WAL, network egress-deny behaviour, 231-test suite, recovery matrix or power cuts. A successful probe is **only Tier-0 platform feasibility**, not permission to touch production or change any production gate.

No additional files, workflows, dependencies or cloud facilities are approved by this test description.
