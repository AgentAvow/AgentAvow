"""Add signing_key to alert_webhooks.

Alert webhooks were delivered unsigned. signing_key holds the per-webhook HMAC secret,
encrypted at rest. Nullable: a webhook saved before this has no secret and is delivered
unsigned until its owner rotates one. Purely additive.

Revision ID: t22
Revises: t21
Create Date: 2026-09-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t22"
down_revision = "t21"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_webhooks", sa.Column("signing_key", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("alert_webhooks", "signing_key")
