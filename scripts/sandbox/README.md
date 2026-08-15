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

## How it works
1. A private Docker network with **no default route to the internet**.
2. A **tinyproxy** sidecar on that network is the *only* egress path; it logs every host
   the target requests.
3. The target runs under **`--runtime=runsc`** (gVisor), **read-only root**, **no host
   mounts**, dropped caps, CPU/mem/pids-capped, `HTTP(S)_PROXY` pointed at the proxy, and a
   hard wall-clock **timeout** (kill after N seconds).
4. On exit we collect the proxy's host log → **observed egress**, plus the exit code and
   whether it timed out. Phase 1 diffs egress against an allowlist / the tool's declared
   hosts and emits behavioral findings.

## Known Phase-0 limitations (hardened in Phase 1)
- Egress capture is **proxy-env based** — malware that ignores `HTTP_PROXY` and dials raw
  sockets would evade it. **Phase 1: transparent redirect** (iptables in the target's
  netns forces all egress through the proxy, so it can't be bypassed), plus raw-connection
  logging and filesystem/process capture from the sandbox layer.
- No artifact materialization yet (you pass an image+command); Phase 1 fetches the npm
  tarball / pip package / MCP repo and runs its install hook + import automatically.
