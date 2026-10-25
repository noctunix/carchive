"""Add `data_points.field_generic` and `catalog_entries.description`.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-23

Does not import `carchive.storage.schema` or `carchive.core.fields`, so this migration
stays frozen even as those modules keep evolving: the generalization regex below is a
byte-for-byte copy of `core.fields.generic_field_name` as it existed when this migration
was written, not a live reference to it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# Batched so a vehicle with millions of data points is backfilled without holding them all
# in memory or in one giant transaction.
_BACKFILL_BATCH_SIZE = 2000

_BRACKET_INDEX = re.compile(r"\[\d+\]")


def _generic_field_name(name: str) -> str:
    text = _BRACKET_INDEX.sub(".[*]", name).replace("..[*]", ".[*]")
    return ".".join("[*]" if part.isdigit() else part for part in text.split("."))


def _backfill_field_generic(connection: sa.engine.Connection) -> None:
    """Fill `field_generic` for every pre-existing `data_points` row, in batches."""
    # `id` is deliberately untyped (no `sa.Uuid`): this backfill never interprets it, only
    # carries it back into the `WHERE` clause, and SQLAlchemy's SQLite `Uuid` type expects
    # its own 32-hex-digit storage format, which a plain passthrough avoids depending on.
    data_points = sa.table(
        "data_points",
        sa.column("id"),
        sa.column("field_name", sa.String()),
        sa.column("field_generic", sa.String()),
    )
    update_statement = (
        sa.update(data_points)
        .where(data_points.c.id == sa.bindparam("_id"))
        .values(field_generic=sa.bindparam("_field_generic"))
    )

    last_id = None
    while True:
        query = sa.select(data_points.c.id, data_points.c.field_name).order_by(data_points.c.id)
        if last_id is not None:
            query = query.where(data_points.c.id > last_id)
        rows = connection.execute(query.limit(_BACKFILL_BATCH_SIZE)).all()
        if not rows:
            break

        connection.execute(
            update_statement,
            [
                {"_id": row.id, "_field_generic": _generic_field_name(row.field_name)}
                for row in rows
            ],
        )
        last_id = rows[-1].id
        if len(rows) < _BACKFILL_BATCH_SIZE:
            break


def upgrade() -> None:
    """Add both columns and backfill `data_points.field_generic` for existing rows."""
    op.add_column("catalog_entries", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("data_points", sa.Column("field_generic", sa.String(), nullable=True))

    _backfill_field_generic(op.get_bind())

    op.create_index(
        "ix_data_points_vehicle_id_field_generic",
        "data_points",
        ["vehicle_id", "field_generic"],
    )


def downgrade() -> None:
    """Drop the index and both columns."""
    op.drop_index("ix_data_points_vehicle_id_field_generic", table_name="data_points")
    op.drop_column("data_points", "field_generic")
    op.drop_column("catalog_entries", "description")
