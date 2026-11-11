"""Add last_decision and last_certified to private_scan_results.

The GitHub App private-repo re-scan (src/jobs/app_scan.py) now alerts on the same
rules as the watch re-scan loop (migrations t27, t28): when a connected repo's answer
gets worse (safe -> review -> do_not_connect, from src/scanner/verdict.py decide()) or its
Certified mark comes off, and it sends a good-news note when either improves. It needs
the answer and the mark it saw last time. Both columns are nullable and purely
additive: existing rows set the baseline silently on their next re-scan and alert
only from the change after that.

Revision ID: t29
Revises: t28
Create Date: 2026-11-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t29"
down_revision = "t28"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "private_scan_results", sa.Column("last_decision", sa.String(32), nullable=True),
    )
    op.add_column(
        "private_scan_results", sa.Column("last_certified", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("private_scan_results", "last_certified")
    op.drop_column("private_scan_results", "last_decision")
