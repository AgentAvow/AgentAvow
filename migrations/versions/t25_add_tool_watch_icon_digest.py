"""Add last_icon_digest to tool_watches.

MCP tools (and resources, prompts, serverInfo) can carry ``icons``. The signed
per-tool digest (agentavow.mcp-tool-definition.v1) does not hash them and stays
unchanged, so an icon can change after approval without any drift showing. The
watch re-scan loop now keeps an unsigned fingerprint of a watched MCP server's icons
(src/scanner/mcp_icons.compute_icon_fingerprint) and alerts "icon changed" when it
moves. Nullable and purely additive: existing watches set the baseline silently on
their next re-scan and alert only from the change after that.

Revision ID: t25
Revises: t24
Create Date: 2026-10-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t25"
down_revision = "t24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tool_watches", sa.Column("last_icon_digest", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tool_watches", "last_icon_digest")
