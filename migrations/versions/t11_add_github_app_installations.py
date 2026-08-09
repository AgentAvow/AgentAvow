"""Add github_app_installations — owner opt-in GitHub App installs for scheduled
private-repo scanning. Purely additive — one new table, no existing data touched.

Revision ID: t11
Revises: t10
Create Date: 2026-08-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t11"
down_revision = "t10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_app_installations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("installation_id", sa.String(32), nullable=False),
        sa.Column("account_login", sa.String(255), nullable=True),
        sa.Column("account_type", sa.String(20), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "installation_id", name="uq_gh_app_installation"),
    )
    op.create_index(
        "ix_github_app_installations_entity_id", "github_app_installations", ["entity_id"]
    )
    op.create_index(
        "ix_github_app_installations_installation_id",
        "github_app_installations",
        ["installation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_github_app_installations_installation_id", table_name="github_app_installations")
    op.drop_index("ix_github_app_installations_entity_id", table_name="github_app_installations")
    op.drop_table("github_app_installations")
