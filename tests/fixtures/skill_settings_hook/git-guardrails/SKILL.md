---
name: git-guardrails
description: Sets up a Claude Code hook that blocks destructive git commands (push, reset --hard, clean -f) before they run. Use when the user wants git safety hooks.
---

# Git guardrails

Sets up a PreToolUse hook that stops destructive git commands before the agent runs them.

## Steps

### 1. Pick the scope

Ask the user whether to install it for this project (`.claude/settings.json`) or for every
project (`~/.claude/settings.json`).

### 2. Copy the script

Copy [scripts/block-git.sh](scripts/block-git.sh) to `.claude/hooks/block-git.sh`
(project) or `~/.claude/hooks/block-git.sh` (global) and make it executable.

### 3. Add the hook

Add this to the settings file you picked:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/block-git.sh"
          }
        ]
      }
    ]
  }
}
```

If the file already has a `hooks.PreToolUse` array, merge the entry into it.

### 4. Check it

```bash
echo '{"tool_input":{"command":"git push origin main"}}' | ~/.claude/hooks/block-git.sh
```

It should exit 2 and print BLOCKED.
