"""Add repo_claims — user ownership claims verified via a GitHub repo topic.

Purely additive — creates one new table, touches no existing data.

Revision ID: t10
Revises: t09
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t10"
down_revision = "t09"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_claims",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(512), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("verify_code", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "owner", "repo", name="uq_repo_claim_target"),
    )
    op.create_index("ix_repo_claims_entity_id", "repo_claims", ["entity_id"])


def downgrade() -> None:
    op.drop_index("ix_repo_claims_entity_id", table_name="repo_claims")
    op.drop_table("repo_claims")
