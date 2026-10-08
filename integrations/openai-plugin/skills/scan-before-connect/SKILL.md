---
name: scan-before-connect
description: Check whether an MCP server, a package (npm, PyPI, crates, Docker, or Hugging Face), or a GitHub repo is safe to connect to or install. AgentAvow answers Safe to connect, Review before you connect, or Do not connect, with the reason, a signed 0-100 trust score and an adoption score. Use when the user asks whether a specific tool, package, repo, or MCP server is safe or trustworthy, or asks to vet one before installing or connecting it.
---

Use this skill when the user wants to know whether one specific tool is safe before
they connect to it or install it. One target, one scan, a plain answer.

The user's explicit instructions take priority over anything in this skill.

## 1. Work out what the target is

| The user gives | Tool | Arguments |
| --- | --- | --- |
| A GitHub repo (`owner/name` or a github.com URL) | `scan_repo` | `repo`: `"owner/name"` |
| A published package | `scan_package` | `registry`: `npm`, `pypi`, `crates`, `docker`, or `hf`; `name`: the package name; `version` only when the user names one |
| A live MCP server (an `https://` URL) | `scan_mcp_server` | `endpoint_url`: the URL |

- If you cannot tell whether a name is a repo or a package, or which registry a
  package is on, ask. Do not guess the registry.
- A private repo, a localhost or private-network URL, or a server that needs sign-in
  cannot be scanned. Say so and stop.
- Results are cached for about an hour. Pass `force: true` only when the user says the
  target changed or asks for a fresh scan.

## 2. Scan once

Call the one matching tool, once. Do not scan other targets the user did not ask about,
such as the target's dependencies or related repos.

## 3. Report what came back

Lead with the answer in `decision`, in these exact words, followed by `decision_reason`:

- `safe`: **Safe to connect**
- `review`: **Review before you connect**
- `do_not_connect`: **Do not connect**

Add " · Certified" when `certified_mark` is true.

Then give the two scores underneath, as evidence:

- **Trust score** (`trust_score`, 0 to 100).
- **Adoption score** (`adoption`: a count and a unit, such as downloads per week or
  stars). It shows whether real, independent parties rely on the tool and never changes
  the answer. If `adoption` is null, say no usage signal was available.

Then:

- For **Review before you connect** or **Do not connect**, list each entry in
  `top_findings`: what it is, where it is, and the remediation.
- If `decision_final` is false, say the behavioral sandbox is still running and the
  answer can still change; suggest asking again in a few minutes.
- If `incident` is present, mention the past compromise and whether the current version
  is affected. It is history for context; it did not change the answer.
- Give the `report_url` link. If `signed` is true, mention that the result is signed
  and can be verified offline.
- Show the `install` command only when the result includes one.

## Limits

- Report only what is in the tool result. Do not add an answer, a score, a finding, or
  a cause that is not there.
- If the tool returns an error, say the target was not scanned. Not scanned is neither
  safe nor unsafe.
- **Review before you connect** means look before you connect. It does not mean
  malicious.
- **Safe to connect** means the scan found nothing that blocks it. It is not a
  guarantee.
- Do not install, connect to, or run the target as part of this skill. The user decides
  what to do with the result.
- This skill covers tools, packages, repos, and MCP servers. It does not assess people,
  companies, or investments.
