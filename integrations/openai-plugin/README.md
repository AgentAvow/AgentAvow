# AgentAvow plugin for ChatGPT and Codex

The package OpenAI's plugin directory takes: the remote MCP server at
`https://agentavow.com/mcp` plus one skill, `scan-before-connect`, that tells the model
which scan tool fits a repo, package, or MCP server and how to report the verdict
without overstating it.

```
plugin.json                          manifest: identity, listing text, release notes
mcp.json                             the one remote MCP server
skills/scan-before-connect/SKILL.md  the skill
assets/logo.png                      listing icon (512x512)
```

## Build

```bash
python3 scripts/build_openai_plugin.py --check   # validate against OpenAI's limits
python3 scripts/build_openai_plugin.py           # write dist/agentavow-openai-plugin-<version>.zip
```

Only `plugin.json`, `mcp.json`, `skills/`, and `assets/` go into the ZIP. This README
does not.

## Rules that are easy to break

- **`name` is fixed.** It is the package name the portal assigned. An update with a
  different name is rejected (`plugin_name_mismatch`).
- **Every upload needs a new `version`.**
- **Listing text, the skill, and assets change only through a new ZIP**, and each new
  ZIP is reviewed again. Tool changes on the MCP server do not need a ZIP; the portal
  rescans the server.
- **No hooks.** A ZIP with lifecycle hooks cannot be submitted, so the Claude Code
  plugin's SessionStart hook has no counterpart here.
- **Keep the skill provider-neutral** ("the model", not a product name), and have it act
  only when the user asks about a specific target. AgentAvow never forces a scan.
- **Screenshots** are optional. If you add them: one per starter prompt, PNG or JPEG,
  exactly 706 px wide and 400–860 px tall.

Before uploading an update, download the current release ZIP from the portal and run
`python3 scripts/build_openai_plugin.py --compare <release.zip>`. It fails on anything
an update must not change.
