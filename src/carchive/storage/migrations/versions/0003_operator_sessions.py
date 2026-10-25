"""Add `operator_sessions`: login sessions of the single operator.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-23

Does not import `carchive.storage.schema`, so this migration stays frozen even as that
module keeps evolving.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from carchive.storage.types import UTCDateTime

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """Create `operator_sessions`."""
    op.create_table(
        "operator_sessions",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("last_seen_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_operator_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_operator_sessions_token_hash"),
    )


def downgrade() -> None:
    """Drop `operator_sessions`."""
    op.drop_table("operator_sessions")
