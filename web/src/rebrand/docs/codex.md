# Use AgentAvow in Codex

Codex can ask AgentAvow whether an MCP server, package or repo is safe to connect. It
gets back **Safe to connect**, **Review before you connect** or **Do not connect**, with
the reason and a signed 0-100 trust score.

## Add the connector

Run this once:

```
codex mcp add agentavow --url https://agentavow.com/mcp
```

Or add the same server to `~/.codex/config.toml` yourself:

```
[mcp_servers.agentavow]
url = "https://agentavow.com/mcp"
```

No account, API key or sign-in is needed. The Codex CLI, the IDE extension and the
ChatGPT desktop app share this file. To use it in one project only, put the block in
that project's `.codex/config.toml` (trusted projects only). Run `codex mcp list`, or
`/mcp` inside Codex, to see that it is connected.

## Add the skill

The scan-before-connect skill tells Codex to check a tool before it connects to it or
installs it, and how to report the answer. Codex reads skills from `~/.agents/skills`
(all your projects) or `.agents/skills` in a repo. This copies it into your own folder:

```
mkdir -p ~/.agents/skills/scan-before-connect/agents
curl -fsSL -o ~/.agents/skills/scan-before-connect/SKILL.md https://raw.githubusercontent.com/AgentAvow/AgentAvow/main/integrations/openai-plugin/skills/scan-before-connect/SKILL.md
curl -fsSL -o ~/.agents/skills/scan-before-connect/agents/openai.yaml https://raw.githubusercontent.com/AgentAvow/AgentAvow/main/integrations/openai-plugin/skills/scan-before-connect/agents/openai.yaml
```

Read it first if you like: [the skill on GitHub](https://github.com/AgentAvow/AgentAvow/tree/main/integrations/openai-plugin/skills/scan-before-connect).
It needs the connector above. Codex picks up new skills on its own; restart it if the
skill doesn't show up. Codex uses it when you ask about a tool, or type
`$scan-before-connect` to call it by name.

## Try it

Ask Codex (use any package name):

```
Is the npm package chalk safe to connect?
```

## Automatic checks (Codex CLI)

The AgentAvow plugin checks your MCP servers each time a session starts, and stops a
`codex mcp add` or package install when the answer is Do not connect. It includes the
connector and the skill above, so you don't need those steps too. Install it with:

```
codex plugin marketplace add AgentAvow/AgentAvow
codex plugin add agentavow-trust@agentavow
```

Codex asks you to review the plugin's hooks the next time it starts. Choose
**Trust all and continue**, or trust them later with `/hooks`. Codex asks again after each
plugin update, and the checks only run while the hooks are trusted.

When the answer is Do not connect, the plugin stops that step and tells you why, with a
link to the report. Codex can't ask you first, so if you've read the report and still want
the server, run the same command yourself outside Codex. The IDE extension doesn't run
plugins yet; the connector and skill above work there.
