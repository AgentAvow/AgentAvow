# Behavioral sandbox

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

## v2 runner — MCP servers, container images, canaries (2026-10-01)

`behavioral_run_v2.sh` is a superset of `behavioral_run.sh` (v1 stays on the box untouched
until v2 is proven). It adds `--mode exec|mcp|image`, `--files-b64` (the app ships the
in-container launcher + exerciser per run, so the host needs nothing from us),
`--canary <value>` (reported as `canary_exfil` when seen in a DNS name or plaintext HTTP),
port-80 capture, and the exerciser's transcript as `exercise`. Output is documented at the
top of the script (`schema: behavioral-v2`).

What ships into the container per run (from `scripts/sandbox/` on the app host):
- `mcp_launch.sh` — finds up to 3 runnable entry points of the installed package and runs the
  exerciser against each until one initializes.
- `mcp_exercise.py` / `mcp_exercise.js` + `synthetic_args.py` — the exerciser: MCP handshake,
  `tools/list`, one `tools/call` per tool with deterministic synthetic arguments, per-call
  filesystem diff, canary detection; prints the transcript defined in
  `src/scanner/behavioral/transcript.py`. Graders: `src/scanner/behavioral/graders.py`.

Deploy v2:
1. Copy `behavioral_run_v2.sh` to the sandbox box (new path, e.g.
   `/home/ec2-user/behavioral_run_v2.sh`), `chmod +x`.
2. Smoke as root: `./behavioral_run_v2.sh node:20-alpine 'npm install left-pad && node -e "require(\"left-pad\")"'`
   (expect `schema: behavioral-v2` and the same hosts as v1), then
   `./behavioral_run_v2.sh --mode image hello-world ''` (expect `image_pulled: true`, image gone after).
3. Set `SCANNER_BEHAVIORAL_SANDBOX_RUNNER_V2=/home/ec2-user/behavioral_run_v2.sh` on the app
   host (empty = v2 off, v1 behavior byte-identical). Optional: `SCANNER_BEHAVIORAL_MAX_TOOLS`,
   `SCANNER_BEHAVIORAL_MCP_TIMEOUT`.
4. Eval: `python scripts/sandbox/eval/run_eval.py --fixtures` (graders against the fixture
   servers, no sandbox needed) and `--sandbox` / `--known-good` (real sandbox; see the script).
