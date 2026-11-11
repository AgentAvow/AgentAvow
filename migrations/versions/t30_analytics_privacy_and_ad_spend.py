"""Hash analytics IPs, store a coarse UA class, and add the ad_spend table.

Three additive changes for the admin metrics dashboard (2026-11-11):

* ``analytics_events.ip_hash`` (nullable): new events store sha256(daily salt | IP)
  instead of the raw IP. ``ip_address`` stays for the rows already written; nothing
  here touches them (backfill / expiry is a separate follow-up).
* ``analytics_events.ua_class`` (nullable): bot | browser | unknown, from the
  User-Agent at write time. The UA itself is never stored. The funnel leaves out bot.
* ``ad_spend``: paid-campaign spend per day per utm_campaign / utm_content, entered by
  the admin, for cost per lp_view and per copy_plugin_cmd.

Revision ID: t30
Revises: t29
Create Date: 2026-11-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t30"
down_revision = "t29"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analytics_events", sa.Column("ip_hash", sa.String(32), nullable=True))
    op.add_column("analytics_events", sa.Column("ua_class", sa.String(16), nullable=True))
    op.create_table(
        "ad_spend",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("utm_source", sa.String(200), nullable=True),
        sa.Column("utm_campaign", sa.String(200), nullable=False),
        sa.Column("utm_content", sa.String(200), nullable=False, server_default=""),
        sa.Column("spend_usd", sa.Numeric(12, 2), nullable=False),
        sa.Column("impressions", sa.Integer(), nullable=True),
        sa.Column("clicks", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.UniqueConstraint("day", "utm_campaign", "utm_content",
                            name="uq_ad_spend_day_campaign_content"),
    )
    op.create_index("ix_ad_spend_day", "ad_spend", ["day"])


def downgrade() -> None:
    op.drop_index("ix_ad_spend_day", table_name="ad_spend")
    op.drop_table("ad_spend")
    op.drop_column("analytics_events", "ua_class")
    op.drop_column("analytics_events", "ip_hash")
