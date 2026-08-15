#!/usr/bin/env bash
# AgentAvow Trust Scan — CI script
# Calls the public AgentAvow API and formats results as a PR comment.
set -euo pipefail

API_BASE="https://agentgraph.co/api/v1/public/scan"
OWNER="${REPO_OWNER}"
REPO="${REPO_NAME}"
MIN_SCORE="${MIN_SCORE:-60}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-false}"
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
SCORE=$(jq -r '.score // 0' /tmp/ag_scan.json)
# 0-100 trust tier word (dual-mark thresholds 80/60/40/20)
if   [ "${SCORE}" -ge 80 ]; then TIER="Trusted"
elif [ "${SCORE}" -ge 60 ]; then TIER="Standard"
elif [ "${SCORE}" -ge 40 ]; then TIER="Caution"
elif [ "${SCORE}" -ge 20 ]; then TIER="Restricted"
else TIER="Blocked"; fi
SUMMARY=$(jq -r '.summary // "No summary available"' /tmp/ag_scan.json)

# Category scores — build a markdown table
CATEGORIES=$(jq -r '
  .categories // {} | to_entries[]
  | "| \(.key) | \(.value) |"
' /tmp/ag_scan.json)

# Findings counts
CRITICAL=$(jq -r '.findings.critical // 0' /tmp/ag_scan.json)
HIGH=$(jq -r '.findings.high // 0' /tmp/ag_scan.json)
MEDIUM=$(jq -r '.findings.medium // 0' /tmp/ag_scan.json)
LOW=$(jq -r '.findings.low // 0' /tmp/ag_scan.json)

REPORT_URL="https://agentavow.com/check/${OWNER}/${REPO}"
BADGE_URL="${API_BASE}/${OWNER}/${REPO}/badge"

echo "Score: ${SCORE}/100 (${TIER})"
echo "Findings: ${CRITICAL} critical, ${HIGH} high, ${MEDIUM} medium, ${LOW} low"
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

echo "AgentAvow Trust Scan complete. Score: ${SCORE}/100"
