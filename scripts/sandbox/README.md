# Behavioral sandbox — Phase 0 prototype

The behavioral tier runs an untrusted tool **in isolation and records what it does** —
which hosts it phones home to, what it writes, what it spawns. This dir is the Phase-0
prototype of the runner. Full plan: `docs/internal/sandbox-behavioral-tier-plan.md`.

> ⚠️ Runs untrusted code. **Never run on the prod box** (it holds signing keys and is
> memory-tight). Stand up a **dedicated, disposable Linux instance**. gVisor is confirmed
> viable on x86_64 AL2023 (ptrace platform, since the instance has no `/dev/kvm`).

## One-time host setup (dedicated instance)
```bash
# install gVisor (runsc) as an additional Docker runtime
ARCH=$(uname -m)
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}/runsc" -o /usr/local/bin/runsc
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}/containerd-shim-runsc-v1" -o /usr/local/bin/containerd-shim-runsc-v1
chmod 0755 /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
runsc install            # adds the "runsc" runtime to /etc/docker/daemon.json
systemctl restart docker # ONLY safe on the dedicated instance, never prod
docker run --rm --runtime=runsc hello-world   # smoke test the isolation layer
```

## Run a behavioral scan (prototype)
```bash
# scan the observable behavior of a command in an image, behind an egress-logging proxy
./behavioral_run.sh node:20-alpine 'npm install left-pad && node -e "require(\"left-pad\")"'
# → prints the JSON BehavioralResult: {egress_hosts, exit_code, timed_out, ...}
```

## How it works (Phase 1)
1. The target runs under **`--runtime=runsc`** (gVisor), **read-only root**, **no host
   mounts**, dropped caps, `no-new-privileges`, CPU/mem/pids-capped, and a hard wall-clock
   **timeout** (killed after N seconds).
2. Egress is captured **passively** with `tcpdump` **inside the container's own network
   namespace** (`nsenter -t <pid> -n`) — DNS query names + TLS SNI. Because it's kernel-level
   packet capture, not a proxy, the target **cannot bypass it** by ignoring `HTTP_PROXY`.
3. Filesystem writes come from `docker diff` (added/changed paths, minus the ephemeral
   tmpfs mounts).
4. Output is a JSON `BehavioralResult` = `{egress_hosts, fs_writes, exit_code, timed_out}`.
   The Python orchestrator (`src/scanner/behavioral/`) diffs `egress_hosts` against the
   package registries + the tool's declared hosts, and turns unexpected egress into a
   signed **behavioral** finding.

## Validate on the dedicated instance
This runner is written for a gVisor host and hasn't been executed on prod (by design).
Before wiring it into the pipeline, on the dedicated instance:
```bash
sudo ./behavioral_run.sh node:20-alpine 'npm install left-pad && node -e "require(\"left-pad\")"'
# expect: egress_hosts ⊇ ["registry.npmjs.org"], no unexpected hosts, fs writes under node_modules/
```
Needs `tcpdump` + root (for `nsenter`). Note gVisor uses a user-space netstack; confirm the
in-netns capture sees the sandbox's egress on your kernel/gVisor platform, and fall back to
capturing on the container's `veth`/bridge if not.

## Still ahead (Phase 1.5)
- **Process capture** (what the target spawned) — via a runsc/ptrace hook or auditd.
- **Automatic artifact materialization** — the Python layer currently drives npm/pypi via
  `install + import`; add MCP stdio (`list-tools`) and richer per-surface exercise.
