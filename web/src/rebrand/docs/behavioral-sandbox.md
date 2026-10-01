# Behavioral sandbox

The static scan reads a tool. The behavioral sandbox **runs** it and reports what it actually did.
The two are kept apart on purpose: the signed score is recomputable from the code alone, and the
sandbox result is an observation attached beside it. A sandbox run never changes a grade.

## What runs

| Target | What the sandbox does |
|---|---|
| npm or PyPI package | Installs it and imports it, so install hooks and import-time code execute. |
| MCP server published as a package | Installs it, starts it over stdio, completes the MCP handshake, lists its tools, and **calls every tool** with synthetic arguments. |
| Container image | Runs the image's own entrypoint for a bounded time. |
| GitHub repo | Runs when the repo maps to a published package; otherwise there is nothing defined to execute. |
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
for a day. Add `?behavioral=true` to a package scan URL, or press **Run behavioral analysis** on the
score page, to force a fresh run.
