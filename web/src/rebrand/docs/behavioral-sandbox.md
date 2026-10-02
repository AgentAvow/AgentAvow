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
| MCP server reached by URL | Not run. Calling tools on someone else's live server could have real side effects, so remote servers get definition analysis only. If the same server ships as a package, scan the package. |
| Rust crates, Hugging Face models, OpenClaw skills | Static analysis only today. |

Each run is a fresh **gVisor** container on a dedicated host: read-only root, no capabilities,
one CPU, 512 MB, a hard time limit. It is destroyed when the run ends. Nothing from one run can
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

## What the findings mean

| Finding | Meaning | Severity |
|---|---|---|
| Undeclared egress | Contacted a host outside the registry and the declared scope | medium, critical at 3+ hosts |
| Read-only annotation violated | A tool declared `readOnlyHint: true` and wrote files when called | high |
| Open-world annotation violated | Every tool declares `openWorldHint: false`, yet the server reached undeclared hosts | medium |
| Credential canary exfiltrated | A canary credential appeared in outbound traffic | critical |
| Canary echoed in result | A tool returned an environment secret in its output | medium |
| Tool call crashed the server | The server exited during a call | low |

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
| Any high behavioral finding (undeclared egress, a read-only tool that wrote files) | −10 and capped at 70, so the verdict is always "needs review" |
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

## Triggering a run

A sandbox run starts automatically the first time a supported package is scanned, from any client:
the Check page, the public API, the GitHub Action, or the AgentAvow MCP server. The result is cached
for a day. Add `?behavioral=true` to a package scan URL, or press **Run now** (**Re-run behavioral analysis**
once a result exists) on the score page, to force a fresh run.

## Where the result shows up

- **Score page**: the sandbox panel, which updates itself while a run is in progress.
- **Watches**: a watched tool whose later run adds findings, an exfiltrated canary, or a new
  undeclared host raises a behavioral-change alert (an in-app notification and an HMAC-signed webhook).
- **GitHub Action**: a `Sandbox:` line in the output and PR comment; set `fail_on_behavioral: true`
  to fail the build on a high or critical sandbox finding. The trust-score gate (`min_score`) is separate.
- **AgentAvow MCP server**: the scan result carries a `Sandbox:` line: a clean run and where it
  sent traffic, the behavioral findings, or why the server did not start (not a finding).
- **Claude Code plugin**: the session-start verdict line carries a sandbox clause, for example
  `sandbox: clean, 9 tool(s) exercised`, the finding count, or why the server was not exercised.
- **Catalog**: tools with a sandbox result carry a mark in Browse.
