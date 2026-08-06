"""Add alert_webhooks — per-account webhook for grade-change alert delivery.

One row per entity. The watch re-scan loop POSTs here on a grade change.
Purely additive — creates one new table, touches no existing data.

Revision ID: t09
Revises: t08
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t09"
down_revision = "t08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_webhooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", name="uq_alert_webhook_entity"),
    )


def downgrade() -> None:
    op.drop_table("alert_webhooks")
