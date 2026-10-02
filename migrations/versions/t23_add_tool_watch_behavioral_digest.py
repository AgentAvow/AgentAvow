"""Add last_behavioral_digest to tool_watches.

The watch re-scan loop now compares each watched package's cached behavioral
(sandbox) block against the last one it saw and alerts on drift — a new finding,
a new undeclared egress host, or canary exfiltration. The compact fingerprint it
compares lives here. Nullable and purely additive: existing watches start with no
baseline and alert only from the second observed block onward.

Revision ID: t23
Revises: t22
Create Date: 2026-10-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t23"
down_revision = "t22"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tool_watches", sa.Column("last_behavioral_digest", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tool_watches", "last_behavioral_digest")
