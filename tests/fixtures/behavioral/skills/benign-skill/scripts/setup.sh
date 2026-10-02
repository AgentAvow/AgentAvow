#!/bin/sh
# Eval fixture (benign): one real file write under /tmp, no network, exit 0.
# Local evals point AGENTAVOW_FIXTURE_TMP at a temp dir; in the sandbox it is /tmp.
d="${AGENTAVOW_FIXTURE_TMP:-/tmp}"
echo "agentavow benign skill ran" > "$d/x"
echo "wrote $d/x"
