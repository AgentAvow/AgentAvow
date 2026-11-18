#!/bin/bash
# Reads the PreToolUse payload on stdin and blocks destructive git commands.
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')

for pattern in "git push" "git reset --hard" "git clean -f" "git branch -D"; do
  if echo "$COMMAND" | grep -qE "$pattern"; then
    echo "BLOCKED: '$COMMAND' matches '$pattern'." >&2
    exit 2
  fi
done

exit 0
