#!/usr/bin/env bash
# ============================================================================
# AgentGraph Production Database Backup (on-host)
# ============================================================================
# Runs ON the EC2 instance via cron. Dumps PostgreSQL from Docker, compresses,
# rotates old backups, and optionally uploads to S3.
#
# Retention policy:
#   - Daily backups: keep last 7
#   - Weekly backups (Sunday): keep last 4
#
# Usage:
#   ./scripts/backup.sh
#
# Cron (daily at 3:00 AM UTC — add to ec2-user crontab):
#   0 3 * * * /home/ec2-user/agentgraph/scripts/backup.sh
#
# Environment variables (optional):
#   S3_BACKUP_BUCKET  — S3 bucket name for off-site backup (e.g. agentgraph-backups)
#   BACKUP_DIR        — Override backup directory (default: /home/ec2-user/backups)
#   CONTAINER_NAME    — Override Docker container name (default: agentgraph-postgres-1)
#   PG_USER           — Override PostgreSQL user (default: agentgraph)
#   PG_DB             — Override PostgreSQL database (default: agentgraph)
#   LOG_FILE          — Override log file path (default: /var/log/agentgraph-backup.log)
#
# Exit codes:
#   0 — Success
#   1 — Backup failed (pg_dump, compression, or directory creation error)
#   2 — S3 upload failed (backup itself succeeded)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BACKUP_DIR="${BACKUP_DIR:-/home/ec2-user/backups}"
CONTAINER_NAME="${CONTAINER_NAME:-agentgraph-postgres-1}"
PG_USER="${PG_USER:-agentgraph}"
PG_DB="${PG_DB:-agentgraph}"
LOG_FILE="${LOG_FILE:-/var/log/agentgraph-backup.log}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
DAY_OF_WEEK="$(date +%u)"  # 1=Monday, 7=Sunday
DAILY_DIR="${BACKUP_DIR}/daily"
WEEKLY_DIR="${BACKUP_DIR}/weekly"
DAILY_KEEP=7
WEEKLY_KEEP=4
BACKUP_FILENAME="agentgraph-${TIMESTAMP}.sql.gz"

# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------
log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] [${level}] ${msg}" | tee -a "${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Failure email notification
# ---------------------------------------------------------------------------
ENV_FILE="/home/ec2-user/agentgraph/.env.production"
# Recipient for failure mail. Cron does not load .env.production, so read it from
# the file when the environment does not set it. This is the backup alert address,
# separate from the app's ADMIN_EMAIL (which names the admin account).
BACKUP_ALERT_EMAIL="${BACKUP_ALERT_EMAIL:-$(grep '^BACKUP_ALERT_EMAIL=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2-)}"
BACKUP_ALERT_EMAIL="${BACKUP_ALERT_EMAIL:-admin@agentavow.com}"

send_failure_email() {
    local error_line="$1"
    local subject="[AgentAvow] Backup FAILED"
    local body="AgentAvow backup FAILED at line ${error_line} on $(date).\n\nCheck logs: /home/ec2-user/backups/backup.log"
    if [ "${error_line}" = "test" ]; then
        subject="[AgentAvow] Backup alert test"
        body="Test message from scripts/backup.sh on $(hostname) at $(date). If you can read this, backup failure alerts reach this address."
    fi
    # Source SMTP creds from .env.production if available
    if [ -f "${ENV_FILE}" ]; then
        local smtp_host smtp_port smtp_user smtp_pass from_email
        smtp_host="$(grep '^SMTP_HOST=' "${ENV_FILE}" | cut -d= -f2-)"
        smtp_port="$(grep '^SMTP_PORT=' "${ENV_FILE}" | cut -d= -f2-)"
        smtp_user="$(grep '^SMTP_USER=' "${ENV_FILE}" | cut -d= -f2-)"
        smtp_pass="$(grep '^SMTP_PASSWORD=' "${ENV_FILE}" | cut -d= -f2-)"
        from_email="$(grep '^FROM_EMAIL=' "${ENV_FILE}" | cut -d= -f2-)"

        if [ -n "${smtp_host}" ] && [ -n "${smtp_user}" ]; then
            # The send result is logged either way: a silent send failure looked
            # like a delivered alert for months.
            local result
            result="$(python3 -c "
import smtplib
from email.mime.text import MIMEText
msg = MIMEText('${body}'.replace('\\\\n', '\\n'))
msg['Subject'] = '${subject}'
msg['From'] = '${from_email}'
msg['To'] = '${BACKUP_ALERT_EMAIL}'
try:
    s = smtplib.SMTP('${smtp_host}', ${smtp_port:-587}, timeout=20)
    s.starttls()
    s.login('${smtp_user}', '${smtp_pass}')
    s.send_message(msg)
    s.quit()
    print('SENT')
except Exception as e:
    print(f'FAILED: {e}')
" 2>&1 || true)"
            if [ "${result}" = "SENT" ]; then
                log "INFO" "Alert email sent to ${BACKUP_ALERT_EMAIL}"
            else
                log "ERROR" "Alert email to ${BACKUP_ALERT_EMAIL} not sent: ${result}"
            fi
        else
            log "ERROR" "Alert email not sent: SMTP_HOST/SMTP_USER missing in ${ENV_FILE}"
        fi
    fi
}

# `backup.sh --test-email` sends one test message to the alert address and exits.
if [ "${1:-}" = "--test-email" ]; then
    send_failure_email "test"
    exit 0
fi

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
on_error() {
    log "ERROR" "Backup FAILED at line $1"
    send_failure_email "$1"
    exit 1
}
trap 'on_error $LINENO' ERR

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "INFO" "========== AgentGraph Backup Started =========="
log "INFO" "Timestamp: ${TIMESTAMP}"
log "INFO" "Container: ${CONTAINER_NAME}"
log "INFO" "Database: ${PG_DB}"

# Create backup directories
mkdir -p "${DAILY_DIR}" "${WEEKLY_DIR}"
log "INFO" "Backup directories verified: ${DAILY_DIR}, ${WEEKLY_DIR}"

# ---------------------------------------------------------------------------
# Step 1: Dump database via docker exec + pg_dump, pipe through gzip
# ---------------------------------------------------------------------------
log "INFO" "Running pg_dump inside container '${CONTAINER_NAME}'..."
docker exec "${CONTAINER_NAME}" \
    pg_dump -U "${PG_USER}" -d "${PG_DB}" --no-owner --no-acl \
    | gzip > "${DAILY_DIR}/${BACKUP_FILENAME}"

FILESIZE="$(du -h "${DAILY_DIR}/${BACKUP_FILENAME}" | cut -f1)"
log "INFO" "Daily backup saved: ${DAILY_DIR}/${BACKUP_FILENAME} (${FILESIZE})"

# ---------------------------------------------------------------------------
# Step 2: Weekly copy (every Sunday)
# ---------------------------------------------------------------------------
if [ "${DAY_OF_WEEK}" -eq 7 ]; then
    cp "${DAILY_DIR}/${BACKUP_FILENAME}" "${WEEKLY_DIR}/${BACKUP_FILENAME}"
    log "INFO" "Weekly backup copied: ${WEEKLY_DIR}/${BACKUP_FILENAME}"
fi

# ---------------------------------------------------------------------------
# Step 3: Rotate old backups
# ---------------------------------------------------------------------------
log "INFO" "Rotating daily backups (keeping last ${DAILY_KEEP})..."
DAILY_REMOVED=0
if [ -d "${DAILY_DIR}" ]; then
    while IFS= read -r old_file; do
        log "INFO" "  Removing old daily: ${old_file}"
        rm -f "${DAILY_DIR}/${old_file}"
        DAILY_REMOVED=$((DAILY_REMOVED + 1))
    done < <(ls -1t "${DAILY_DIR}"/agentgraph-*.sql.gz 2>/dev/null | tail -n +$((DAILY_KEEP + 1)) | xargs -n1 basename 2>/dev/null || true)
fi
log "INFO" "Removed ${DAILY_REMOVED} old daily backup(s)"

log "INFO" "Rotating weekly backups (keeping last ${WEEKLY_KEEP})..."
WEEKLY_REMOVED=0
if [ -d "${WEEKLY_DIR}" ]; then
    while IFS= read -r old_file; do
        log "INFO" "  Removing old weekly: ${old_file}"
        rm -f "${WEEKLY_DIR}/${old_file}"
        WEEKLY_REMOVED=$((WEEKLY_REMOVED + 1))
    done < <(ls -1t "${WEEKLY_DIR}"/agentgraph-*.sql.gz 2>/dev/null | tail -n +$((WEEKLY_KEEP + 1)) | xargs -n1 basename 2>/dev/null || true)
fi
log "INFO" "Removed ${WEEKLY_REMOVED} old weekly backup(s)"

# ---------------------------------------------------------------------------
# Step 4: Optional S3 upload
# ---------------------------------------------------------------------------
S3_EXIT=0
if [ -n "${S3_BACKUP_BUCKET:-}" ]; then
    if command -v aws &>/dev/null; then
        log "INFO" "Uploading to S3: s3://${S3_BACKUP_BUCKET}/daily/${BACKUP_FILENAME}"
        if aws s3 cp "${DAILY_DIR}/${BACKUP_FILENAME}" \
                "s3://${S3_BACKUP_BUCKET}/daily/${BACKUP_FILENAME}" \
                --only-show-errors; then
            log "INFO" "S3 upload succeeded (daily)"
        else
            log "ERROR" "S3 upload FAILED for daily backup"
            S3_EXIT=2
        fi

        # Upload weekly copy too
        if [ "${DAY_OF_WEEK}" -eq 7 ]; then
            if aws s3 cp "${WEEKLY_DIR}/${BACKUP_FILENAME}" \
                    "s3://${S3_BACKUP_BUCKET}/weekly/${BACKUP_FILENAME}" \
                    --only-show-errors; then
                log "INFO" "S3 upload succeeded (weekly)"
            else
                log "ERROR" "S3 upload FAILED for weekly backup"
                S3_EXIT=2
            fi
        fi
    else
        log "WARN" "AWS CLI not found — skipping S3 upload"
    fi
else
    log "INFO" "S3_BACKUP_BUCKET not set — skipping S3 upload"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
REMAINING_DAILY="$(find "${DAILY_DIR}" -name 'agentgraph-*.sql.gz' 2>/dev/null | wc -l | tr -d ' ')"
REMAINING_WEEKLY="$(find "${WEEKLY_DIR}" -name 'agentgraph-*.sql.gz' 2>/dev/null | wc -l | tr -d ' ')"
log "INFO" "Backup summary: ${REMAINING_DAILY} daily, ${REMAINING_WEEKLY} weekly backups on disk"
log "INFO" "========== AgentGraph Backup Finished =========="

exit "${S3_EXIT}"
