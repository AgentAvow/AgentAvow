#!/usr/bin/env bash
# AgentAvow Trust Scan — CI script
# Calls the public AgentAvow API and formats results as a PR comment.
set -euo pipefail

API_BASE="https://agentavow.com/api/v1/public/scan"
OWNER="${REPO_OWNER}"
REPO="${REPO_NAME}"
MIN_SCORE="${MIN_SCORE:-60}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-false}"
FAIL_ON_BEHAVIORAL="${FAIL_ON_BEHAVIORAL:-false}"
COMMENT_ON_PR="${COMMENT_ON_PR:-true}"
PR_NUMBER="${PR_NUMBER:-}"

# ---------------------------------------------------------------------------
# 1. Call the AgentAvow public scan API
# ---------------------------------------------------------------------------
echo "::group::AgentAvow Trust Scan"
echo "Scanning ${OWNER}/${REPO} ..."

HTTP_CODE=$(curl -s -o /tmp/ag_scan.json -w "%{http_code}" \
  "${API_BASE}/${OWNER}/${REPO}")

if [ "$HTTP_CODE" -ne 200 ]; then
  echo "::error::AgentAvow API returned HTTP ${HTTP_CODE}"
  cat /tmp/ag_scan.json 2>/dev/null || true
  echo "::endgroup::"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Parse the JSON response
# ---------------------------------------------------------------------------
# The public scan API returns `trust_score`, `scan_result`, `category_scores` and a
# `findings` object with per-severity counts. The older names are kept as fallbacks.
# A response with no score at all is an API problem, not a 0/100 verdict: stop.
SCORE=$(jq -r '.trust_score // .score // empty' /tmp/ag_scan.json)
if [ -z "${SCORE}" ] || [ "${SCORE}" = "null" ]; then
  echo "::error::AgentAvow API response carried no trust_score; not posting a verdict"
  head -c 600 /tmp/ag_scan.json 2>/dev/null || true
  echo "::endgroup::"
  exit 1
fi
# 0-100 trust tier word (dual-mark thresholds 80/60/40/20)
if   [ "${SCORE}" -ge 80 ]; then TIER="Trusted"
elif [ "${SCORE}" -ge 60 ]; then TIER="Standard"
elif [ "${SCORE}" -ge 40 ]; then TIER="Caution"
elif [ "${SCORE}" -ge 20 ]; then TIER="Restricted"
else TIER="Blocked"; fi
# One-line summary: the API's own if present, else derived from the scan result.
SUMMARY=$(jq -r '
  .summary //
  (if .deprecation then "Deprecated upstream — do not adopt for new work"
   elif .scan_result == "clean" then "Clean — no blocking findings"
   elif .scan_result then "Scan result: \(.scan_result)"
   else "See the full report" end)
' /tmp/ag_scan.json)

# Category scores — build a markdown table (snake_case keys shown as words)
CATEGORIES=$(jq -r '
  (.category_scores // .categories // {}) | to_entries[]
  | "| \(.key | gsub("_"; " ")) | \(.value) |"
' /tmp/ag_scan.json)

# Findings counts. The API reports critical/high/medium and a total; "low" is what is
# left of the total once the three named severities are taken out.
CRITICAL=$(jq -r '.findings.critical // 0' /tmp/ag_scan.json)
HIGH=$(jq -r '.findings.high // 0' /tmp/ag_scan.json)
MEDIUM=$(jq -r '.findings.medium // 0' /tmp/ag_scan.json)
LOW=$(jq -r '
  .findings.low //
  ([(.findings.total // 0) - (.findings.critical // 0) - (.findings.high // 0)
    - (.findings.medium // 0), 0] | max)
' /tmp/ag_scan.json)

REPORT_URL="https://agentavow.com/check/${OWNER}/${REPO}"
BADGE_URL="${API_BASE}/${OWNER}/${REPO}/badge"

# Behavioral sandbox tier (present when the repo maps to an npm/PyPI/docker package
# the sandbox has exercised; absent otherwise). Kept SEPARATE from the signed score.
B_RAN=$(jq -r '.behavioral.ran // false' /tmp/ag_scan.json)
B_PENDING=$(jq -r '.behavioral.pending // false' /tmp/ag_scan.json)
B_SEVERE=0
SANDBOX_LINE=""
if [ "${B_RAN}" = "true" ]; then
  B_PLAN=$(jq -r '.behavioral.plan // "install"' /tmp/ag_scan.json)
  B_TOOLS=$(jq -r '[.behavioral.exercise.calls[]?.tool] | unique | length' /tmp/ag_scan.json)
  B_FINDINGS=$(jq -r '[.behavioral.findings[]?] | length' /tmp/ag_scan.json)
  B_SEVERE=$(jq -r '[.behavioral.findings[]? | select(.severity == "high" or .severity == "critical")] | length' /tmp/ag_scan.json)
  B_HOSTS=$(jq -r '[.behavioral.unexpected_egress[]?] | join(", ")' /tmp/ag_scan.json)
  B_HOSTS_N=$(jq -r '[.behavioral.unexpected_egress[]?] | length' /tmp/ag_scan.json)
  B_STARTED=$(jq -r '.behavioral.exercise.launch_ok // false' /tmp/ag_scan.json)
  B_REASON=$(jq -r '.behavioral.grade_summary.start_reason // ""' /tmp/ag_scan.json | tr '_' ' ')
  B_LEAK=$(jq -r '[.behavioral.canary_exfil[]?] | length' /tmp/ag_scan.json)
  B_DELTA=$(jq -r 'if (.behavioral_score_effect.applied // false) then (.behavioral_score_effect.delta | tostring) else "" end' /tmp/ag_scan.json)
  if [ "${B_STARTED}" = "true" ]; then
    SANDBOX_LINE="Sandbox (gVisor, signed): called ${B_TOOLS} tool(s), ${B_FINDINGS} behavioral finding(s)"
  elif [ -n "${B_REASON}" ] && [ "${B_REASON}" != "not applicable" ] && [ "${B_REASON}" != "started" ]; then
    SANDBOX_LINE="Sandbox (gVisor, signed): installed; server not started (${B_REASON}) — not a finding; ${B_FINDINGS} behavioral finding(s)"
  else
    SANDBOX_LINE="Sandbox (gVisor, signed): plan ${B_PLAN}, ${B_TOOLS} tool(s) exercised, ${B_FINDINGS} behavioral finding(s)"
  fi
  if [ "${B_LEAK}" -gt 0 ]; then
    SANDBOX_LINE="${SANDBOX_LINE}, CANARY CREDENTIAL LEAKED"
  fi
  if [ "${B_HOSTS_N}" -gt 0 ]; then
    SANDBOX_LINE="${SANDBOX_LINE}, unexpected egress: ${B_HOSTS}"
  else
    SANDBOX_LINE="${SANDBOX_LINE}, no unexpected egress"
  fi
  if [ -n "${B_DELTA}" ]; then
    case "${B_DELTA}" in -*) ;; *) B_DELTA="+${B_DELTA}" ;; esac
    SANDBOX_LINE="${SANDBOX_LINE}; trust score ${B_DELTA} from the sandbox"
  fi
elif [ "${B_PENDING}" = "true" ]; then
  SANDBOX_LINE="Sandbox: running now — the observed behavior (and its effect on the score) appears on the next scan"
fi

echo "Score: ${SCORE}/100 (${TIER})"
echo "Findings: ${CRITICAL} critical, ${HIGH} high, ${MEDIUM} medium, ${LOW} low"
if [ -n "${SANDBOX_LINE}" ]; then
  echo "${SANDBOX_LINE}"
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------
# 3. Build the PR comment body
# ---------------------------------------------------------------------------
COMMENT_BODY="## AgentAvow Trust Scan

**AgentAvow Trust: ${SCORE}/100 (${TIER})** — ${SUMMARY}

| Category | Score |
|----------|-------|
${CATEGORIES}

**Findings:** ${CRITICAL} critical, ${HIGH} high, ${MEDIUM} medium, ${LOW} low
${SANDBOX_LINE:+
**${SANDBOX_LINE}**
}
[View full report](${REPORT_URL}) | [Add badge to README](${BADGE_URL})

> *This is a code security scan score. [Full composite trust score](${REPORT_URL}) (including identity verification and external signals) is available on AgentAvow.*"

# ---------------------------------------------------------------------------
# 4. Post comment on PR (if enabled and this is a PR event)
# ---------------------------------------------------------------------------
if [ "${COMMENT_ON_PR}" = "true" ] && [ -n "${PR_NUMBER}" ]; then
  echo "Posting comment on PR #${PR_NUMBER} ..."

  # Delete any previous AgentAvow comment to avoid clutter
  PREVIOUS_COMMENT_ID=$(curl -s \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
    | jq -r '.[] | select(.body | startswith("## AgentAvow Trust Scan")) | .id' \
    | head -1)

  if [ -n "${PREVIOUS_COMMENT_ID}" ] && [ "${PREVIOUS_COMMENT_ID}" != "null" ]; then
    curl -s -X DELETE \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/comments/${PREVIOUS_COMMENT_ID}" \
      > /dev/null
    echo "Deleted previous scan comment (${PREVIOUS_COMMENT_ID})"
  fi

  # Post fresh comment
  PAYLOAD=$(jq -n --arg body "${COMMENT_BODY}" '{"body": $body}')
  curl -s -X POST \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
    -d "${PAYLOAD}" > /dev/null

  echo "Comment posted."
else
  echo "Skipping PR comment (comment_on_pr=${COMMENT_ON_PR}, PR_NUMBER=${PR_NUMBER})"
fi

# ---------------------------------------------------------------------------
# 5. Write GitHub Actions job summary
# ---------------------------------------------------------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "${COMMENT_BODY}" >> "${GITHUB_STEP_SUMMARY}"
fi

# ---------------------------------------------------------------------------
# 6. Fail if score is below threshold and fail_on_findings is true
# ---------------------------------------------------------------------------
if [ "${FAIL_ON_FINDINGS}" = "true" ] && [ "${SCORE}" -lt "${MIN_SCORE}" ]; then
  echo "::error::Trust score ${SCORE} is below minimum threshold ${MIN_SCORE}"
  exit 1
fi

# 7. Fail on a high/critical BEHAVIORAL finding (sandbox tier) when opted in.
#    A pending or absent sandbox run never fails the step.
if [ "${FAIL_ON_BEHAVIORAL}" = "true" ] && [ "${B_SEVERE}" -gt 0 ]; then
  echo "::error::Sandbox observed ${B_SEVERE} high/critical behavioral finding(s)"
  exit 1
fi

echo "AgentAvow Trust Scan complete. Score: ${SCORE}/100"
