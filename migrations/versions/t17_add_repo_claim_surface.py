"""Multi-surface claims — add repo_claims.surface ('github' default) + proof_method,
widen repo to 512 (MCP endpoint URLs), and fold surface into the uniqueness key so a
github repo and an openclaw skill sharing owner/repo don't collide. Purely additive;
existing rows default to github and are unchanged.

Revision ID: t17
Revises: t16
Create Date: 2026-08-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t17"
down_revision = "t16"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repo_claims",
        sa.Column("surface", sa.String(length=16), nullable=False, server_default="github"),
    )
    op.add_column(
        "repo_claims",
        sa.Column("proof_method", sa.String(length=24), nullable=True),
    )
    op.alter_column(
        "repo_claims", "repo",
        existing_type=sa.String(length=255), type_=sa.String(length=512),
    )
    op.drop_constraint("uq_repo_claim_target", "repo_claims", type_="unique")
    op.create_unique_constraint(
        "uq_repo_claim_target", "repo_claims", ["entity_id", "surface", "owner", "repo"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_repo_claim_target", "repo_claims", type_="unique")
    op.create_unique_constraint(
        "uq_repo_claim_target", "repo_claims", ["entity_id", "owner", "repo"],
    )
    op.alter_column(
        "repo_claims", "repo",
        existing_type=sa.String(length=512), type_=sa.String(length=255),
    )
    op.drop_column("repo_claims", "proof_method")
    op.drop_column("repo_claims", "surface")
