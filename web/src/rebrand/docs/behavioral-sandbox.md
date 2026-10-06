# Behavioral sandbox

The static scan reads a tool. The behavioral sandbox **runs** it and reports what it actually did.
The run is signed as its own dated observation, and that signed observation is also an input to the
trust score, by fixed rules anyone can recompute (see [How the sandbox moves the score](#how-the-sandbox-moves-the-score)).

## What runs

| Target | What the sandbox does |
|---|---|
| npm or PyPI package | Installs it and imports it, so install hooks and import-time code execute. |
| MCP server published as a package | Installs it, starts it over stdio, completes the MCP handshake, lists its tools, and **calls every tool** with synthetic arguments. |
| Container image | Runs the image's own entrypoint for a bounded time. |
| GitHub repo | Runs the package the repo publishes. A JavaScript/TypeScript or Python repo with no published package is installed straight from GitHub instead (and exercised as an MCP server if it is one). Other repos have nothing defined to execute. |
| MCP server reached by URL | Not run automatically. Calling tools on someone else's live server could have real side effects, so remote servers get definition analysis only. On the score page (or `?probe=true` on the API) you can opt in to a **live probe**: it calls only tools whose annotations declare them read-only (and not destructive), at most 10, once each, with synthetic inputs, and reports what came back — injection text or a credential-looking value in a result, a read-only tool that errors. The probe is advisory and never scored: a live answer cannot be recomputed by a verifier. Use it on servers you own or are allowed to test. If the same server ships as a package, scan the package for the full sandbox run. |
| OpenClaw / Agent Skill | Cloned; its lifecycle hooks (`hooks.json`, `plugin.json`), bundled MCP servers (`.mcp.json`, sent `initialize`) and bundled scripts are run with canary credentials, each with no arguments and its own timeout; network and file writes observed. |
| Rust crates, Hugging Face models | Static analysis only today. |

Each run is a fresh **gVisor** container on a dedicated host: read-only root, no capabilities,
one CPU, 1 GB of memory, a hard time limit. It is destroyed when the run ends. Nothing from one run can
reach the next, and nothing in the sandbox can reach a private network.

## What is observed

- **Network egress**: every DNS lookup and TLS server name, plus plaintext HTTP. Hosts outside the
  package registry and the tool's [declared scope](./check-guide.md#declare-your-tools-scope-optional) are flagged,
  with two deterministic exceptions: a host that belongs to the tool's own vendor by name (a search tool
  named after its vendor calling that vendor's API is shown as "vendor", not flagged), and `example.com`,
  which is where the synthetic arguments point a URL-taking tool.
- **Filesystem writes**: new files under the writable mounts, attributed to the tool call that made them.
- **Tool transcript** (MCP servers): the tools the server advertised with their annotations, the
  arguments each was called with, whether the call succeeded, how long it took, and what it wrote.
- **Entrypoint transcript** (skills): every hook, bundled MCP server and bundled script found, whether
  each started and how it exited, how long it ran, and what it wrote. A skill that ships nothing
  runnable is reported as not exercised, which is never a finding.
- **Canary credentials**: the static scan sees which environment variables the tool reads. The
  sandbox fills each with a unique fake value. If that value leaves the machine in a DNS query or
  an HTTP body, that is credential exfiltration and is graded critical. If a tool returns it in a
  result, that is reported too. **No real credential ever enters the sandbox.**

## How arguments are chosen

Synthetic arguments are generated **deterministically** from each tool's own input schema:
examples and defaults first, then enums, then formats such as URL, email, path, and date. Examples
in the package's README are used when they name the tool. The same tool with the same schema always
gets the same arguments, so a run can be repeated and compared. No language model writes the calls;
a model's output is not reproducible, and the result has to be.

## The SSRF probe

Any tool that takes a URL is also handed one extra argument: a sentinel pointing at a link-local
address (`169.254.254.254`), an address a router never forwards, so the request can reach no real
system. A well-behaved tool resolves the host, sees it is internal, and refuses. A tool that builds
the request without checking where the URL resolves connects to it, and the sandbox's host-side
capture records the attempt. That is the exact flaw behind the 2026 wave of MCP server-side request
forgery reports (Google's `MCP Toolbox for Databases`, CVE-2026-14540, and others): a server that
turns a caller-supplied URL into an outbound request with no target validation, so an agent can
steer it at cloud-metadata or internal services. Only package-shipped servers are probed this way;
a remote server you point us at is never handed the sentinel.

## What the findings mean

| Finding | Meaning | Severity |
|---|---|---|
| Followed a caller-supplied URL to an internal address | A tool was handed a link-local URL and connected to it, so it builds outbound requests from URLs the caller controls without checking the target (server-side request forgery) | high |
| Undeclared egress | Contacted a host outside the registry, the tool's own vendor, and the declared scope | high |
| Read-only annotation violated | A tool declared `readOnlyHint: true` and wrote files when called | high |
| Open-world annotation violated | Every tool declares `openWorldHint: false`, yet the server reached undeclared hosts | medium |
| Credential canary exfiltrated | A canary credential appeared in outbound traffic | critical |
| Canary echoed in result | A tool returned an environment secret in its output | medium |
| Tool call crashed the server | The server exited during a call | low |
| Contacted the cloud instance-metadata service | Reached `169.254.169.254` or another metadata address. Normal for a tool built on a cloud SDK, which looks for credentials there; a red flag for a tool that has no reason to | low (note only) |
| Skill entrypoint contacted an undeclared host | The one hook, server or script a skill ran reached a host outside GitHub and the declared scope; named only when exactly one entrypoint ran, since egress is captured for the whole run | medium |

## When a server does not start

Many servers need something the sandbox will not supply: a real API key, a URL or path on the
command line, a program the image lacks, or more memory than a browser download allows. The
result says which (`needs_credentials`, `needs_arguments`, `missing_binary`, `install_failed`,
`resource_limit`, `no_entrypoint`, `timeout`, `crashed`) and the tools are reported as **not
exercised**. That is never a finding and never lowers a score. Where a server only needs a
credential, the sandbox retries once with a canary value so the server can get as far as its
first authenticated call.

## The observation is signed

Every completed run carries a `BehavioralObservation` attestation: a JWS over the hosts, writes,
tool calls and findings you see, with the sandbox plan and the date, signed with the same key
as the score. See [Verify an attestation](./verify-attestations.md#behavioral-observations).

## How the sandbox moves the score

Only a **signed, completed** run counts. Applied to the score from the static scan, in this order:

| What the sandbox observed | Effect on the trust score |
|---|---|
| A canary credential left the sandbox, or any critical behavioral finding | Capped at 45, the same as a shipped critical in code |
| Any high behavioral finding (undeclared egress, a read-only tool that wrote files, following a caller-supplied URL to an internal address) | −10 and capped at 70, so the verdict is always "needs review" |
| Medium behavioral findings only | −5 |
| Low findings (a crash) | No change |
| A clean, full exercise: the server started, tools were called, nothing was found | +3, for evidence nobody else has |
| Still running, not run, server did not start, install-only, or unsigned | No change |

The score attestation records the evidence as `scan.behavioralEvidence`: the SHA-256 of the
observation's JWS, the static score, the findings, and the resulting delta. With the observation in
hand, anyone recomputes the same number. Because a sandbox result is cached for a day and the first
scan of a package returns before the run finishes, a package's score can move once, shortly after
it is first scanned.

## What the sandbox cannot prove

A clean run means the tool did nothing bad **under these conditions**. It does not prove the tool
is safe. Code that waits for a date, checks for a real credential, detects a sandbox, or fetches its
payload later will look clean. That is why a sandbox result is shown as an observation, why the
static scan still looks for sandbox-probing and time-conditional code, and why
[watching](./check-guide.md#stay-safe-over-time) a tool for definition drift matters more than any
single run.

## When runs happen

- **First look.** The first time anyone scans a supported package, repo, or skill, from any client, a sandbox run starts within a minute. The result is kept for a day.
- **When the tool changes.** The catalog is re-scanned on a schedule. When a package publishes a new version, or a server's tool definitions change, its sandbox result is discarded and a fresh run is queued. A tool cannot start behaving differently without shipping a change, so this is the cadence that matters.
- **Watched tools** are kept current and you are alerted when their observed behavior changes.
- **The long tail** is backfilled in the background, most-used first, using only sandbox capacity that real scans aren't using.
- **On demand.** Add `?behavioral=true` to a package scan URL, or press **Run now** on the score page, for a fresh run.

We don't re-run every tool on a calendar: most tools don't change from week to week, and a run that observes the same version again adds nothing.

## How we check ourselves

A fixed corpus runs through the real sandbox every week: fixture servers with known-bad behavior that must be caught, and a set of popular, well-maintained servers and skills on which any finding counts as a false positive until a person says otherwise. The results, and a diff against the previous week, are reviewed, and a regression raises an alert. The same fixtures also run in our test suite on every change.

## Where the result shows up

- **Score page**: the sandbox panel, which updates itself while a run is in progress.
- **Watches**: a watched tool whose later run adds findings, an exfiltrated canary, or a new
  undeclared host raises a behavioral-change alert (an in-app notification and an HMAC-signed webhook).
- **GitHub Action**: a `Sandbox:` line in the output and PR comment; set `fail_on_behavioral: true`
  to fail the build on a high or critical sandbox finding. The trust-score gate (`min_score`) is separate.
- **AgentAvow MCP server**: the scan result carries a `Sandbox:` line: a clean run and where it
  sent traffic, the behavioral findings, or why the server did not start (not a finding).
- **Claude Code plugin**: the session-start verdict line carries a sandbox clause, for example
  `sandbox: called 9 tools, no network beyond the registry`, `sandbox: CAUGHT a planted credential leaving
  the sandbox (critical) +1 more`, `sandbox: not started (needs credentials)`, or `sandbox: running now,
  results in about a minute`.
- **Catalog**: tools with a sandbox result carry a mark in Browse.
