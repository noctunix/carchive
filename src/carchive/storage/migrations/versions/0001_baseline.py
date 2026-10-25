"""Baseline schema: every MVP table, written out as explicit DDL.

Revision ID: 0001
Revises:
Create Date: 2026-10-22

Does not import `carchive.storage.schema`, so this migration stays frozen even as that
module keeps evolving.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from carchive.storage.types import UTCDateTime

revision: str = "0001"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """Create every table of the MVP schema, in foreign-key dependency order."""
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=False),
        sa.Column("brand", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("credential_ref", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("state_reason", sa.String(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_accounts"),
        sa.UniqueConstraint("label", name="uq_accounts_label"),
        sa.CheckConstraint(
            "state IN ('active', 'needs_attention', 'disabled')", name="ck_accounts_valid_state"
        ),
    )

    op.create_table(
        "backups",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_backups"),
    )

    op.create_table(
        "catalog_entries",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=False),
        sa.Column("catalog_version", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("unit", sa.String(), nullable=True),
        sa.Column("data_type", sa.String(), nullable=True),
        sa.Column("clusters", sa.JSON(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_catalog_entries"),
        sa.UniqueConstraint(
            "provider_id",
            "catalog_version",
            "key",
            name="uq_catalog_entries_provider_id_catalog_version_key",
        ),
        sa.CheckConstraint(
            "kind IN ('continuous', 'historical')", name="ck_catalog_entries_valid_kind"
        ),
    )

    op.create_table(
        "vehicles",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("account_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vin", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("brand", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("archived_at", UTCDateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_vehicles"),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name="fk_vehicles_account_id_accounts"
        ),
        sa.UniqueConstraint("account_id", "vin", name="uq_vehicles_account_id_vin"),
    )

    op.create_table(
        "data_requests",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vehicle_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("remote_id", sa.String(), nullable=True),
        sa.Column("interval_s", sa.Integer(), nullable=False),
        sa.Column("next_due_at", UTCDateTime(), nullable=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("state_reason", sa.String(), nullable=True),
        sa.Column("last_success_at", UTCDateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_data_requests"),
        sa.ForeignKeyConstraint(
            ["vehicle_id"], ["vehicles.id"], name="fk_data_requests_vehicle_id_vehicles"
        ),
        sa.UniqueConstraint("vehicle_id", "kind", name="uq_data_requests_vehicle_id_kind"),
        sa.CheckConstraint(
            "state IN ('active', 'needs_attention', 'disabled')",
            name="ck_data_requests_valid_state",
        ),
    )

    op.create_table(
        "import_batches",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vehicle_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("source_name", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("progress", sa.Float(), nullable=False),
        sa.Column("started_at", UTCDateTime(), nullable=False),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_import_batches"),
        sa.ForeignKeyConstraint(
            ["vehicle_id"], ["vehicles.id"], name="fk_import_batches_vehicle_id_vehicles"
        ),
        sa.UniqueConstraint("vehicle_id", "sha256", name="uq_import_batches_vehicle_id_sha256"),
        sa.CheckConstraint("kind IN ('historical')", name="ck_import_batches_valid_kind"),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'done', 'failed')",
            name="ck_import_batches_valid_state",
        ),
        sa.CheckConstraint(
            "progress >= 0 AND progress <= 1", name="ck_import_batches_valid_progress"
        ),
    )

    op.create_table(
        "deliveries",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("data_request_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("import_batch_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("remote_name", sa.String(), nullable=False),
        sa.Column("delivered_at", UTCDateTime(), nullable=True),
        sa.Column("fetched_at", UTCDateTime(), nullable=False),
        sa.Column("has_content", sa.Boolean(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("parse_state", sa.String(), nullable=False),
        sa.Column("parser_version", sa.String(), nullable=True),
        sa.Column("raw_payload", sa.LargeBinary(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_deliveries"),
        sa.ForeignKeyConstraint(
            ["data_request_id"],
            ["data_requests.id"],
            name="fk_deliveries_data_request_id_data_requests",
        ),
        sa.ForeignKeyConstraint(
            ["import_batch_id"],
            ["import_batches.id"],
            name="fk_deliveries_import_batch_id_import_batches",
        ),
        sa.UniqueConstraint(
            "data_request_id",
            "remote_name",
            name="uq_deliveries_data_request_id_remote_name",
        ),
        sa.CheckConstraint(
            "(data_request_id IS NULL) != (import_batch_id IS NULL)",
            name="ck_deliveries_exactly_one_parent",
        ),
        sa.CheckConstraint(
            "parse_state IN ('pending', 'parsed', 'failed', 'empty')",
            name="ck_deliveries_valid_parse_state",
        ),
    )

    op.create_table(
        "data_points",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vehicle_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("field_name", sa.String(), nullable=False),
        sa.Column("value_raw", sa.Text(), nullable=True),
        sa.Column("value_type", sa.String(), nullable=False),
        sa.Column("value_num", sa.Float(), nullable=True),
        sa.Column("value_text", sa.Text(), nullable=True),
        sa.Column("value_bool", sa.Boolean(), nullable=True),
        sa.Column("value_time", UTCDateTime(), nullable=True),
        sa.Column("captured_at", UTCDateTime(), nullable=True),
        sa.Column("captured_at_quality", sa.String(), nullable=False),
        sa.Column("first_delivery_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("first_seen_at", UTCDateTime(), nullable=False),
        sa.Column("last_seen_at", UTCDateTime(), nullable=False),
        sa.Column("seen_count", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_data_points"),
        sa.ForeignKeyConstraint(
            ["vehicle_id"], ["vehicles.id"], name="fk_data_points_vehicle_id_vehicles"
        ),
        sa.ForeignKeyConstraint(
            ["first_delivery_id"],
            ["deliveries.id"],
            name="fk_data_points_first_delivery_id_deliveries",
        ),
        sa.UniqueConstraint("vehicle_id", "dedup_key", name="uq_data_points_vehicle_id_dedup_key"),
        sa.CheckConstraint(
            "value_type IN ('num', 'text', 'bool', 'time', 'null')",
            name="ck_data_points_valid_value_type",
        ),
        sa.CheckConstraint(
            "captured_at_quality IN ('exact', 'report', 'delivery', 'tz_unknown', 'invalid')",
            name="ck_data_points_valid_captured_at_quality",
        ),
    )
    op.create_index(
        "ix_data_points_vehicle_id_field_name_captured_at",
        "data_points",
        ["vehicle_id", "field_name", "captured_at"],
    )
    op.create_index(
        "ix_data_points_vehicle_id_key_captured_at",
        "data_points",
        ["vehicle_id", "key", "captured_at"],
    )

    op.create_table(
        "signal_values",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("vehicle_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("signal", sa.String(), nullable=False),
        sa.Column("value_num", sa.Float(), nullable=True),
        sa.Column("value_text", sa.Text(), nullable=True),
        sa.Column("value_bool", sa.Boolean(), nullable=True),
        sa.Column("unit", sa.String(), nullable=True),
        sa.Column("captured_at", UTCDateTime(), nullable=True),
        sa.Column("captured_at_quality", sa.String(), nullable=False),
        sa.Column("source_data_point_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("mapping_version", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_signal_values"),
        sa.ForeignKeyConstraint(
            ["vehicle_id"], ["vehicles.id"], name="fk_signal_values_vehicle_id_vehicles"
        ),
        sa.ForeignKeyConstraint(
            ["source_data_point_id"],
            ["data_points.id"],
            name="fk_signal_values_source_data_point_id_data_points",
        ),
        sa.UniqueConstraint(
            "source_data_point_id",
            "signal",
            "mapping_version",
            name="uq_signal_values_source_data_point_id_signal_mapping_version",
        ),
        sa.CheckConstraint(
            "captured_at_quality IN ('exact', 'report', 'delivery', 'tz_unknown', 'invalid')",
            name="ck_signal_values_valid_captured_at_quality",
        ),
    )
    op.create_index(
        "ix_signal_values_vehicle_id_signal_captured_at",
        "signal_values",
        ["vehicle_id", "signal", "captured_at"],
    )

    op.create_table(
        "collector_runs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("account_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("data_request_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("started_at", UTCDateTime(), nullable=False),
        sa.Column("finished_at", UTCDateTime(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("listed", sa.Integer(), nullable=True),
        sa.Column("placeholders", sa.Integer(), nullable=True),
        sa.Column("downloaded", sa.Integer(), nullable=True),
        sa.Column("with_content", sa.Integer(), nullable=True),
        sa.Column("pending", sa.Integer(), nullable=True),
        sa.Column("oldest_pending_age_s", sa.Float(), nullable=True),
        sa.Column("message", sa.String(length=300), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_collector_runs"),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"], name="fk_collector_runs_account_id_accounts"
        ),
        sa.ForeignKeyConstraint(
            ["data_request_id"],
            ["data_requests.id"],
            name="fk_collector_runs_data_request_id_data_requests",
        ),
        sa.CheckConstraint(
            "outcome IN ('ok', 'unavailable', 'rate_limited', 'error', 'login_failed')",
            name="ck_collector_runs_valid_outcome",
        ),
        sa.CheckConstraint(
            "message IS NULL OR length(message) <= 300", name="ck_collector_runs_message_length"
        ),
    )
    op.create_index(
        "ix_collector_runs_data_request_id_started_at",
        "collector_runs",
        ["data_request_id", "started_at"],
    )


def downgrade() -> None:
    """Drop every table, in reverse dependency order."""
    op.drop_index("ix_collector_runs_data_request_id_started_at", table_name="collector_runs")
    op.drop_table("collector_runs")

    op.drop_index("ix_signal_values_vehicle_id_signal_captured_at", table_name="signal_values")
    op.drop_table("signal_values")

    op.drop_index("ix_data_points_vehicle_id_key_captured_at", table_name="data_points")
    op.drop_index("ix_data_points_vehicle_id_field_name_captured_at", table_name="data_points")
    op.drop_table("data_points")

    op.drop_table("deliveries")
    op.drop_table("import_batches")
    op.drop_table("data_requests")
    op.drop_table("vehicles")
    op.drop_table("catalog_entries")
    op.drop_table("backups")
    op.drop_table("accounts")
