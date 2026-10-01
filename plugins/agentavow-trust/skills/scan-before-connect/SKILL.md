---
name: scan-before-connect
description: Scan an MCP server, a package (npm, PyPI, crates, Docker, Hugging Face), or a GitHub repo with AgentAvow before it is added, installed, or connected. Use when the user asks you to add or install a new MCP server, plugin, package, or tool from a repo, or asks whether one is safe or trustworthy.
---

Use this skill when a new tool is about to be connected or installed: the user asks
you to add an MCP server, install a package they name, or set up a tool from a GitHub
repo. Also use it when the user asks whether one of these is safe. Scan first, report,
then carry on with what the user asked.

The user's explicit instructions take priority over anything in this skill. If they
say to skip the scan, skip it.

## When not to scan

- Installing what a project already declares (`npm install`, `pip install -r
  requirements.txt`, restoring a lockfile). Scan a package only when the user names it
  as something new to add.
- A target already scanned in this conversation.
- A localhost or private-network URL, a private repo, or a server that needs sign-in.
  AgentAvow cannot reach these. Say it was not scanned and continue.
- A URL that contains a key or token in its path or query string. Do not send it. Say
  it was not scanned because the URL carries a secret.

## 1. Work out what the target is

| The target | Tool | Arguments |
| --- | --- | --- |
| A live MCP server (an `https://` URL) | `scan_mcp_server` | `endpoint_url`: the URL, without its query string |
| A published package | `scan_package` | `registry`: `npm`, `pypi`, `crates`, `docker`, or `hf`; `name`: the package name |
| A GitHub repo (`owner/name` or a github.com URL) | `scan_repo` | `repo`: `"owner/name"` |

An MCP server started with `npx` or `bunx` is an npm package; one started with `uvx`
or `pipx` is a PyPI package. If you cannot tell which registry a name belongs to, ask.
Do not guess.

## 2. Scan once, before the install

Call the one matching AgentAvow tool, once, before you run the install or add command.
Do not scan the target's dependencies or related repos. Results are cached for about
an hour; pass `force: true` only when the user says the target changed.

## 3. Report, then continue

Give the score out of 100, the verdict, the top findings with where they are, and the
report link from the result.

- **Safe:** say so in one line and go ahead with what the user asked.
- **Needs review:** show the findings and ask whether to continue. Do not install or
  connect until the user answers.
- **Not scanned** (an error, a timeout, or a target AgentAvow cannot reach): say it was
  not scanned. That is neither safe nor unsafe. Ask whether to continue.

## Limits

- Report only what the tool returned. Do not add a score, a finding, or a cause that
  is not in the result.
- "Needs review" means look before you connect. It does not mean malicious.
- "Safe" means the scan found no blocking issue. It is not a guarantee.
- The scan is advice. The user decides whether to install or connect.
